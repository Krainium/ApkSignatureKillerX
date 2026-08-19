#!/usr/bin/env bash
# decode_integrity.sh — the server side of the Play Integrity check (#19).
#
# The app requests a token on the device (opaque, Google-signed); the verdict is
# meant to be decoded and trusted only on YOUR server. This script is that server
# step: it decodes a token with the Play Integrity API and prints the verdict.
#
# It exists to PROVE the honest boundary: run the demo on a re-signed apk and the
# decoded verdict shows appRecognitionVerdict = UNRECOGNIZED_VERSION with the REAL
# signing cert, even though every in-app signature read was faked. An in-app killer
# cannot move this.
#
# usage:
#   decode_integrity.sh <package> <token-or-logcat-file>
#
# needs: gcloud authed to the GCP project whose number the app passed as
# CLOUD_PROJECT_NUMBER, with playintegrity.googleapis.com enabled.
#
# get the token: the demo logs it to logcat as `TOKENCHUNK <i> <part>` lines
# (logcat truncates long lines). Pass the raw logcat and this script reassembles
# it, or pass a file that already contains the whole token.
set -euo pipefail

PKG="${1:?usage: decode_integrity.sh <package> <token-or-logcat-file>}"
SRC="${2:?usage: decode_integrity.sh <package> <token-or-logcat-file>}"

TOKEN=$(python3 - "$SRC" <<'PY'
import re, sys
data = open(sys.argv[1], errors="ignore").read()
chunks = {int(i): p.rstrip() for i, p in re.findall(r'TOKENCHUNK (\d+) (.+)', data)}
print("".join(chunks[i] for i in sorted(chunks)) if chunks else data.strip())
PY
)

ACCESS=$(gcloud auth print-access-token \
  --scopes="https://www.googleapis.com/auth/playintegrity")

python3 -c "import json,sys;print(json.dumps({'integrity_token':sys.argv[1]}))" "$TOKEN" > /tmp/kx_pi_body.json

curl -sS -X POST \
  "https://playintegrity.googleapis.com/v1/${PKG}:decodeIntegrityToken" \
  -H "Authorization: Bearer ${ACCESS}" \
  -H "Content-Type: application/json" \
  -d @/tmp/kx_pi_body.json | python3 -m json.tool
