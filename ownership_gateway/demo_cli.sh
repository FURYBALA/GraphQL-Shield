#!/usr/bin/env bash
# Backup demo with plain curl, in case the browser misbehaves during the review.
# Requires ./run.sh to be running in another terminal.
GW=http://127.0.0.1:5000; BE=http://127.0.0.1:5001
TOKEN=$(curl -s -XPOST $BE/login -H 'content-type: application/json' -d '{"username":"bob","password":"bob123"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
Q='{"query":"{ record(id: \"101\") { id diagnosis prescription } }"}'
echo "== Bob asks for Alice's medical record 101 DIRECTLY from the backend (vulnerable) =="
curl -s -XPOST $BE/graphql -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$Q"; echo
echo "== Same request THROUGH GraphQLShield =="
curl -s -XPOST $GW/graphql -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$Q"; echo
echo "== Bob tries to overwrite Alice's prescription through GraphQLShield =="
curl -s -XPOST $GW/graphql -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"query":"mutation { updateRecord(id: \"101\", prescription: \"HACKED\") { id } }"}'; echo
