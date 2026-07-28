#!/usr/bin/env bash
# SENTINEL APEX — Continuous Assurance Orchestrator (ECAP v1)
#
# The one entry point for "did everything pass" — identical whether run
# locally before a push, in CI, or as a pre-release check. Invokes existing
# suites and tools verbatim; reimplements none of their logic:
#   - Sentinel-APEX/engine    -> python3 -m pytest        (sentinel_engine)
#   - Sentinel-APEX/renderer  -> node --test              (report renderer)
#   - Sentinel-APEX/engine-node -> node --test            (detection engine)
#   - tests-js                -> node --test              (blog-wide JS)
#   - cli.py gate / certify   -> quality gate + EICF v1 certification,
#                                across every report in reports/published/
#
# All five stages are independent (no ordering dependency), so a full run
# executes every stage and reports a complete summary rather than stopping
# at the first failure — a developer fixing multiple issues sees all of
# them in one pass. The Release Decision at the end is GO only if every
# requested stage passed; that is the one place this script "stops
# progression" per ECAP v1's Phase 6, not the middle of the run.
#
# Known limitation (documented, not silently glossed over): the certify
# stage runs `cli.py certify <report>` with no --html/--sitemap/--index,
# because there is no manifest recording which slug a report was published
# under (publish-report.js's slug is a human-chosen CLI arg, not derived
# from the report filename) — Publication Quality reports "Not Applicable"
# here, not "Pass". Pass --html/--sitemap/--index by hand (see
# `cli.py certify --help`) for full publication-domain coverage of a
# specific already-published report.
#
# Usage:
#   scripts/assure.sh                            # everything
#   scripts/assure.sh --python --renderer         # only the named stages
#   scripts/assure.sh --list                      # print stage names, exit
#
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_PYTHON=0
RUN_RENDERER=0
RUN_ENGINE_NODE=0
RUN_ROOT_JS=0
RUN_CERTIFY=0

if [ "${1:-}" = "--list" ]; then
  echo "python renderer engine-node root-js certify"
  exit 0
fi

if [ $# -eq 0 ]; then
  RUN_PYTHON=1; RUN_RENDERER=1; RUN_ENGINE_NODE=1; RUN_ROOT_JS=1; RUN_CERTIFY=1
else
  for arg in "$@"; do
    case "$arg" in
      --python) RUN_PYTHON=1 ;;
      --renderer) RUN_RENDERER=1 ;;
      --engine-node) RUN_ENGINE_NODE=1 ;;
      --root-js) RUN_ROOT_JS=1 ;;
      --certify) RUN_CERTIFY=1 ;;
      --all) RUN_PYTHON=1; RUN_RENDERER=1; RUN_ENGINE_NODE=1; RUN_ROOT_JS=1; RUN_CERTIFY=1 ;;
      *) echo "unknown flag: $arg (try --python --renderer --engine-node --root-js --certify --all --list)" >&2; exit 2 ;;
    esac
  done
fi

RESULTS=()
OVERALL=0

run_stage() {
  local name="$1"; shift
  echo ""
  echo "════════════════════════════════════════════════════════════"
  echo "▶ ${name}"
  echo "════════════════════════════════════════════════════════════"
  if "$@"; then
    RESULTS+=("PASS  ${name}")
  else
    RESULTS+=("FAIL  ${name}")
    OVERALL=1
  fi
}

if [ "$RUN_PYTHON" = 1 ]; then
  run_stage "Python engine suite (Sentinel-APEX/engine)" \
    bash -c 'cd Sentinel-APEX/engine && python3 -m pytest'
fi

if [ "$RUN_RENDERER" = 1 ]; then
  run_stage "Renderer suite (Sentinel-APEX/renderer)" \
    bash -c 'node --test Sentinel-APEX/renderer/tests/*.test.js'
fi

if [ "$RUN_ENGINE_NODE" = 1 ]; then
  run_stage "Detection engine Node suite (Sentinel-APEX/engine-node)" \
    bash -c 'node --test Sentinel-APEX/engine-node/tests/*.test.js'
fi

if [ "$RUN_ROOT_JS" = 1 ]; then
  run_stage "Root JS suite (tests-js)" \
    bash -c 'node --test tests-js/*.test.js'
fi

if [ "$RUN_CERTIFY" = 1 ]; then
  run_stage "Quality gate + certification (Sentinel-APEX/reports/published)" bash -c '
    cd Sentinel-APEX/engine
    shopt -s nullglob
    reports=(../reports/published/*.md)
    if [ ${#reports[@]} -eq 0 ]; then
      echo "no published reports — nothing to gate/certify"
      exit 0
    fi
    status=0
    echo "--- cli.py gate: ${#reports[@]} report(s) together (enables corpus-level checks) ---"
    python3 cli.py gate "${reports[@]}" || status=1
    for r in "${reports[@]}"; do
      echo ""
      echo "--- cli.py certify: $(basename "$r") ---"
      python3 cli.py certify "$r" || status=1
    done
    exit "$status"
  '
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  CONTINUOUS ASSURANCE SUMMARY — $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "════════════════════════════════════════════════════════════"
for r in "${RESULTS[@]}"; do
  echo "  $r"
done
echo ""
if [ "$OVERALL" -eq 0 ]; then
  echo "  RELEASE DECISION: GO — all requested stages passed."
else
  echo "  RELEASE DECISION: NO-GO — one or more stages failed. See above for which, and re-run after fixing."
fi
echo "════════════════════════════════════════════════════════════"

exit "$OVERALL"
