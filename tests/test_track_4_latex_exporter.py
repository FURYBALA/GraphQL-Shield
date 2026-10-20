"""
Tests for Track 4: One-Click Paper Publication Archive & LaTeX Exporter
========================================================================
Verifies:
1. Publication-ready LaTeX tables generation adhering to standard booktabs formatting.
2. In-memory reproducible research bundle (.zip) construction with all required artifacts:
   - predictions CSV
   - experiment manifest with SHA-256 dataset checksums
   - LaTeX source
   - datasets v1 and v2
   - standalone reproduction script
   - README
3. REST API endpoints:
   - GET /api/v1/research/experiments/{id}/export/latex
   - GET /api/v1/research/experiments/{id}/export/bundle
"""

import io
import json
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.main import app, startup_event
from app.security.research.persistence import get_all_experiments
from app.security.research.evaluator import run_full_experiment
from app.security.research.latex_exporter import (
    generate_latex_tables,
    create_reproducible_research_bundle,
    _escape_latex,
)


@pytest.fixture(scope="module")
def client():
    startup_event()
    return TestClient(app)


@pytest.fixture(scope="module")
def sample_experiment_id():
    startup_event()
    experiments = get_all_experiments()
    if experiments:
        return experiments[0]["id"]
    res = run_full_experiment(
        dataset_id="ds_benchmark_v1",
        name="Test Experiment for LaTeX Exporter",
        include_ablations=True,
    )
    return res["experiment_id"]


def test_escape_latex():
    """Verify LaTeX special character escaping."""
    raw = "User & Admin % 100 $ #1 _secret_ {id} ~ ^"
    escaped = _escape_latex(raw)
    assert r"\&" in escaped
    assert r"\%" in escaped
    assert r"\$" in escaped
    assert r"\#" in escaped
    assert r"\_" in escaped
    assert r"\{" in escaped
    assert r"\}" in escaped


def test_generate_latex_tables(sample_experiment_id):
    """Verify LaTeX table export contains all three publication tables."""
    latex_text = generate_latex_tables(sample_experiment_id)

    assert r"\begin{document}" in latex_text
    assert r"\end{document}" in latex_text
    assert r"\begin{table*}[t]" in latex_text
    assert r"\caption{Comparative Evaluation of GraphQL BOLA Detection and Attribution Methods}" in latex_text
    assert r"\toprule" in latex_text
    assert r"\bottomrule" in latex_text
    assert r"Method A: Static AST Taint Analysis" in latex_text
    assert r"Method C: Correlated AST-Runtime" in latex_text
    assert r"\caption{Ablation Study: Impact of Removing Individual Grounding Layers}" in latex_text
    assert r"\caption{Fine-Grained Path Attribution Accuracy Across Scenario Classes}" in latex_text


def test_generate_latex_tables_not_found():
    """Verify 404/ValueError on invalid experiment ID."""
    with pytest.raises(ValueError, match="not found"):
        generate_latex_tables("non_existent_exp_9999")


def test_create_reproducible_research_bundle(sample_experiment_id):
    """Verify in-memory ZIP bundle contains all necessary reproducible research artifacts."""
    bundle_bytes = create_reproducible_research_bundle(sample_experiment_id)
    assert len(bundle_bytes) > 1000

    with zipfile.ZipFile(io.BytesIO(bundle_bytes), mode="r") as zf:
        namelist = zf.namelist()
        assert f"predictions_{sample_experiment_id}.csv" in namelist
        assert f"manifest_{sample_experiment_id}.json" in namelist
        assert f"ccns_research_tables_{sample_experiment_id}.tex" in namelist
        assert "datasets/ds_benchmark_v1.json" in namelist
        assert "datasets/ds_generalization_v2.json" in namelist
        assert "reproduce_evaluation.py" in namelist
        assert "README.md" in namelist

        # Inspect manifest content
        manifest_str = zf.read(f"manifest_{sample_experiment_id}.json").decode("utf-8")
        manifest_data = json.loads(manifest_str)
        assert "manifest" in manifest_data
        checksums = manifest_data["manifest"].get("dataset_checksums", {})
        assert "ds_benchmark_v1_sha256" in checksums
        assert len(checksums["ds_benchmark_v1_sha256"]) == 64

        # Verify reproduction script is executable python code
        script_content = zf.read("reproduce_evaluation.py").decode("utf-8")
        assert "def main():" in script_content
        assert "McNemar" in script_content


def test_api_export_latex_endpoint(client, sample_experiment_id):
    """Verify GET /api/v1/research/experiments/{id}/export/latex returns 200."""
    resp = client.get(f"/api/v1/research/experiments/{sample_experiment_id}/export/latex")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")
    assert r"\begin{document}" in resp.text
    assert r"\end{document}" in resp.text


def test_api_export_bundle_endpoint(client, sample_experiment_id):
    """Verify GET /api/v1/research/experiments/{id}/export/bundle returns valid zip file."""
    resp = client.get(f"/api/v1/research/experiments/{sample_experiment_id}/export/bundle")
    assert resp.status_code == 200
    assert resp.headers.get("content-type") == "application/zip"
    assert f"ccns_research_bundle_{sample_experiment_id}.zip" in resp.headers.get("content-disposition", "")

    # Validate zip integrity
    with zipfile.ZipFile(io.BytesIO(resp.content), mode="r") as zf:
        namelist = zf.namelist()
        assert "reproduce_evaluation.py" in namelist
        assert "README.md" in namelist
