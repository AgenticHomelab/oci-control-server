#!/usr/bin/env bash
# Offline publication audit only. No source mutation or report upload.
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: scan_public_export.sh CLEAN_TREE PYTHON_VENV" >&2
  exit 2
fi
candidate="$(realpath -- "$1")"
venv="$(realpath -- "$2")"
test -d "$candidate" && test -x "$venv/bin/python"
test ! -e "$candidate/.git"
test ! -d "$candidate/terraform/.terraform"

mkdir -p "$RUNNER_TEMP/public-tools"
GOBIN="$RUNNER_TEMP/public-tools" go install github.com/zricethezav/gitleaks/v8@v8.24.2
"$venv/bin/pip" install --disable-pip-version-check detect-secrets==1.5.0

cd "$candidate"
set +e
"$RUNNER_TEMP/public-tools/gitleaks" dir . --redact --report-format json --report-path "$RUNNER_TEMP/gitleaks-public.json" >/dev/null 2>&1
gitleaks_rc=$?
"$venv/bin/detect-secrets" scan --all-files . > "$RUNNER_TEMP/detect-public.json" 2>/dev/null
detect_rc=$?
set -e

"$venv/bin/python" - "$RUNNER_TEMP/gitleaks-public.json" "$RUNNER_TEMP/detect-public.json" "$gitleaks_rc" "$detect_rc" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

gitleaks_path, detect_path = map(Path, sys.argv[1:3])
gitleaks_rc, detect_rc = map(int, sys.argv[3:])
try:
    leaks = json.loads(gitleaks_path.read_text()) if gitleaks_path.exists() else []
    findings = json.loads(detect_path.read_text())["results"]
    reviewed = json.loads(Path("publication/reviewed-scanner-exceptions.json").read_text())
    if not isinstance(leaks, list) or not isinstance(findings, dict):
        raise ValueError("Unexpected scanner report")
    if reviewed["schema_version"] != 1:
        raise ValueError("Unsupported scanner review schema")
except (OSError, ValueError, KeyError, TypeError):
    print("Secret scanning did not yield valid private reports or a review contract")
    raise SystemExit(1)

# Exceptions are tied to the exact Git blob of a manually inspected source file.
# A changed line, added detector hit or stale exception fails closed.
allowed = set()
try:
    for rel, record in reviewed["files"].items():
        source = Path(rel)
        if source.is_absolute() or ".." in source.parts or not source.is_file():
            raise ValueError("Unreviewable exception source")
        content = source.read_bytes()
        git_header = ("blob " + str(len(content)) + "\0").encode()
        fingerprint = hashlib.sha1(git_header + content).hexdigest()[:16]
        segments = record["git_blob_prefix_segments"]
        if (not isinstance(segments, list) or len(segments) != 4
                or any(not isinstance(x, str) or len(x) != 4 for x in segments)):
            raise ValueError("Invalid reviewed blob digest")
        if fingerprint != "".join(segments):
            print("Scanner review invalidated by source change:", rel)
            raise ValueError("Reviewed source changed")
        for item in record["findings"]:
            key = (item["tool"], rel, item["rule"], int(item["line"]))
            if key in allowed:
                raise ValueError("Duplicate exception")
            allowed.add(key)
except (OSError, ValueError, KeyError, TypeError):
    print("Reviewed scanner exceptions are invalid")
    raise SystemExit(1)

seen = set()
unreviewed = 0
for finding in leaks:
    # Only path, rule name and line are reported. Never include raw matches.
    filename = Path(finding.get("File", "")).as_posix().removeprefix("./")
    key = ("gitleaks", filename, finding.get("RuleID"), int(finding.get("StartLine", 0)))
    if key in allowed:
        seen.add(key)
    else:
        unreviewed += 1
        print("Unreviewed Gitleaks candidate location:", filename,
              "rule:", key[2], "line:", key[3])
for filename, entries in findings.items():
    filename = Path(filename).as_posix().removeprefix("./")
    for finding in entries:
        key = ("detect-secrets", filename, finding.get("type"),
               int(finding.get("line_number", 0)))
        if key in allowed:
            seen.add(key)
        else:
            unreviewed += 1
            print("Unreviewed detect-secrets location:", filename,
                  "type:", key[2], "line:", key[3])

stale = allowed - seen
print(f"Gitleaks: {len(leaks)} raw findings; detect-secrets: "
      f"{sum(map(len, findings.values()))} raw findings; "
      f"{unreviewed} unreviewed; {len(seen)} exact-blob reviewed; {len(stale)} stale")
if (gitleaks_rc not in (0, 1) or detect_rc != 0
        or (gitleaks_rc == 1 and not leaks)
        or unreviewed or stale):
    raise SystemExit(1)
PY
