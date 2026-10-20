"""Experiment runner: compares GraphQLShield against baselines and an ablation.

Requires backend (:5001) and gateway (:5000) running.
Run:  python -m eval.run_eval [--iterations 50]
Writes eval/results/results.json, results.md, detection_matrix.csv and charts (if matplotlib is installed).
With GS_POLICY=policy_fastapi.json (same value the gateway was started with) it evaluates the second target,
the main FastAPI application, and writes to eval/results_fastapi/ instead.

RQ1 Effectiveness : attack prevention rate per mode and per attack category
RQ2 Precision     : false-positive rate on legitimate (benign) requests
RQ3 Overhead      : added latency vs. calling the backend directly
"""
import argparse
import csv
import json
import os
import statistics
import time

import requests

from attacks.runner import load_corpus, run_case, target_config

GATEWAY = os.environ.get("GS_GATEWAY", "http://127.0.0.1:5000")
BACKEND = os.environ.get("GS_BACKEND", "http://127.0.0.1:5001")
MODES = ["off", "depth", "argcheck", "response_only", "shield"]
LABELS = {"off": "No protection", "depth": "Depth/alias limits (hardening baseline)",
          "argcheck": "Argument-level ID check (WAF-style baseline)", "response_only": "Response verification only (ablation)",
          "shield": "GraphQLShield (full)"}
POLICY = json.load(open(os.path.join(os.path.dirname(__file__), "..", "gateway", os.environ.get("GS_POLICY", "policy.json"))))
TARGET = target_config(POLICY)
ATTACKS, BENIGN = load_corpus(TARGET).ATTACKS, load_corpus(TARGET).BENIGN
OUT = os.path.join(os.path.dirname(__file__), TARGET["results_dir"])


def set_mode(mode):
    requests.post(GATEWAY + "/api/mode", json={"mode": mode}, timeout=5).raise_for_status()


def reset():
    requests.post(GATEWAY + "/api/reset", timeout=5).raise_for_status()


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=50)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    requests.post(GATEWAY + "/api/reset?logs=1", timeout=5)

    matrix = {}   # attack id -> mode -> succeeded?
    benign = {}   # benign id -> mode -> passed?
    for mode in MODES:
        set_mode(mode)
        for case in ATTACKS:
            reset()
            matrix.setdefault(case["id"], {})[mode] = run_case(case, GATEWAY, BACKEND, target=TARGET)["succeeded"]
        for case in BENIGN:
            reset()
            r = run_case(case, GATEWAY, BACKEND, user=case["user"], target=TARGET)
            benign.setdefault(case["id"], {})[mode] = r["status"] == 200 and case["expect"] in r["text"]
        print(f"[{mode}] attacks prevented {sum(not matrix[a['id']][mode] for a in ATTACKS)}/{len(ATTACKS)}, "
              f"benign passed {sum(benign[b['id']][mode] for b in BENIGN)}/{len(BENIGN)}")

    # ---- latency (read-only benign queries so state never changes)
    read_only = [b for b in BENIGN if "mutation" not in json.dumps(b["body"])]
    latency = {}
    for target in ["direct"] + MODES:
        if target != "direct":
            set_mode(target)
        reset()
        samples = []
        for _ in range(args.iterations):
            for case in read_only:
                url = BACKEND if target == "direct" else GATEWAY
                samples.append(run_case(case, url, BACKEND, user=case["user"], target=TARGET)["latency_ms"])
        latency[target] = {"p50": round(pct(samples, 50), 2), "p95": round(pct(samples, 95), 2),
                           "mean": round(statistics.mean(samples), 2), "n": len(samples)}
        print(f"[latency {target}] {latency[target]}")
    set_mode("shield")
    reset()

    # ---- summaries
    summary = {}
    for mode in MODES:
        prevented = sum(not matrix[a["id"]][mode] for a in ATTACKS)
        fp = sum(not benign[b["id"]][mode] for b in BENIGN)
        summary[mode] = {"label": LABELS[mode], "attacks_prevented": prevented, "attacks_total": len(ATTACKS),
                         "prevention_rate": round(prevented / len(ATTACKS), 3),
                         "false_positives": fp, "benign_total": len(BENIGN), "fpr": round(fp / len(BENIGN), 3),
                         "p50_ms": latency[mode]["p50"], "p95_ms": latency[mode]["p95"],
                         "p50_overhead_ms": round(latency[mode]["p50"] - latency["direct"]["p50"], 2)}
    categories = {}
    for a in ATTACKS:
        for mode in MODES:
            c = categories.setdefault(a["category"], {}).setdefault(mode, [0, 0])
            c[0] += not matrix[a["id"]][mode]
            c[1] += 1

    result = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "target": TARGET["name"], "iterations": args.iterations, "summary": summary,
              "attack_matrix": matrix, "benign_matrix": benign, "latency": latency, "categories": categories}
    json.dump(result, open(os.path.join(OUT, "results.json"), "w"), indent=2)

    with open(os.path.join(OUT, "detection_matrix.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case", "category", "title"] + MODES)
        for a in ATTACKS:
            w.writerow([a["id"], a["category"], a["title"]] + ["BLOCKED" if not matrix[a["id"]][m] else "LEAKED" for m in MODES])

    md = [f"# GraphQLShield evaluation results\n\nTarget: {TARGET['name']}\n\nGenerated {result['timestamp']} - {len(ATTACKS)} attacks, "
          f"{len(BENIGN)} benign requests, latency over {args.iterations} iterations x {len(read_only)} read-only queries.\n",
          "## Table 1 - Effectiveness, precision and overhead\n",
          "| Configuration | Attacks prevented | Prevention rate | False positives | FPR | p50 latency (ms) | p95 latency (ms) | p50 overhead vs direct (ms) |",
          "|---|---|---|---|---|---|---|---|"]
    for m in MODES:
        s = summary[m]
        md.append(f"| {s['label']} | {s['attacks_prevented']}/{s['attacks_total']} | {s['prevention_rate']:.0%} | "
                  f"{s['false_positives']}/{s['benign_total']} | {s['fpr']:.0%} | {s['p50_ms']} | {s['p95_ms']} | {s['p50_overhead_ms']} |")
    md.append(f"\nDirect backend (no gateway): p50 {latency['direct']['p50']} ms, p95 {latency['direct']['p95']} ms.\n")
    md += ["## Table 2 - Prevention by attack category\n", "| Category | " + " | ".join(MODES) + " |", "|---" * (len(MODES) + 1) + "|"]
    for cat, row in categories.items():
        md.append(f"| {cat} | " + " | ".join(f"{row[m][0]}/{row[m][1]}" for m in MODES) + " |")
    md += ["\n## Table 3 - Per-attack outcome (B = blocked/redacted, L = attack succeeded)\n",
           "| Case | Category | Attack | " + " | ".join(MODES) + " |", "|---" * (len(MODES) + 3) + "|"]
    for a in ATTACKS:
        md.append(f"| {a['id']} | {a['category']} | {a['title']} | " + " | ".join("L" if matrix[a["id"]][m] else "B" for m in MODES) + " |")
    md += ["\n## Table 4 - Benign requests (P = passed, FP = wrongly blocked)\n",
           "| Case | Request | " + " | ".join(MODES) + " |", "|---" * (len(MODES) + 2) + "|"]
    for b in BENIGN:
        md.append(f"| {b['id']} | {b['title']} | " + " | ".join("P" if benign[b["id"]][m] else "**FP**" for m in MODES) + " |")
    open(os.path.join(OUT, "results.md"), "w").write("\n".join(md) + "\n")
    _charts(summary, latency)
    print("\nWrote", OUT)


def _charts(summary, latency):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed - skipping charts)")
        return
    names = ["No protection", "Depth limits", "Arg check", "Response only", "GraphQLShield"]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    x = range(len(MODES))
    ax.bar([i - 0.2 for i in x], [summary[m]["prevention_rate"] * 100 for m in MODES], 0.4, label="Attacks prevented (%)", color="#2a6fdb")
    ax.bar([i + 0.2 for i in x], [summary[m]["fpr"] * 100 for m in MODES], 0.4, label="False-positive rate (%)", color="#d9822b")
    ax.set_xticks(list(x), names, fontsize=8)
    ax.set_ylim(0, 105)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, fontsize=8)
    ax.set_title("Effectiveness vs. precision", fontsize=10)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "effectiveness.png"), dpi=160)

    fig, ax = plt.subplots(figsize=(7, 3.6))
    targets = ["direct"] + MODES
    ax.bar(range(len(targets)), [latency[t]["p50"] for t in targets], 0.4, label="p50", color="#2a6fdb")
    ax.bar([i + 0.4 for i in range(len(targets))], [latency[t]["p95"] for t in targets], 0.4, label="p95", color="#9bb8ea")
    ax.set_xticks([i + 0.2 for i in range(len(targets))], ["Direct"] + names, fontsize=8)
    ax.set_ylabel("ms")
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, fontsize=8)
    ax.set_title("End-to-end latency", fontsize=10)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "latency.png"), dpi=160)


if __name__ == "__main__":
    main()
