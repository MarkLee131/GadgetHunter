#!/bin/bash
#
# Stage 1 of GadgetHunter: run the modified Flash / Tai-e taint analysis to
# produce the over-approximated set of candidate gadget chains (paper §3.3).
#
# Usage:
#   ./run.sh <config.yml>                  analyse one target
#   ./run.sh --batch <targets-dir> [jobs]  analyse every <targets-dir>/*/config.yml
#
# A config.yml names the target's class path, its output directory, and the taint
# configuration to use. See ../../gleipner_results/configs/config_depth.yml for a
# complete example, and gleipner_results/taint-analysis/*/config.yml for the
# configs behind the paper's Table 5 runs.
#
# Candidate chains are written to the file named by GC_OUT inside the config's
# outputDir ("chains" by default). Each run also leaves a log.log next to its
# config, and the analysis writes a `time` file recording its wall clock.
#
# Overridable:
#   FLASH_JAR        path to the analysis jar   (default: ./flash.jar)
#   FLASH_JAVA_OPTS  JVM flags                  (default: -Xss1024m -Xmx24G)
#
# Deep chains need a large stack; the -Xss1024m default matches the paper's runs.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${FLASH_JAR:-$HERE/flash.jar}"
JAVA_OPTS="${FLASH_JAVA_OPTS:--Xss1024m -Xmx24G}"

if [[ ! -f "$JAR" ]]; then
  echo "error: analysis jar not found at $JAR (set FLASH_JAR to override)" >&2
  exit 1
fi

analyse_one() {
  local cfg="$1"
  local dir log

  if [[ ! -f "$cfg" ]]; then
    echo "[MISS] $cfg"
    return 0
  fi

  dir="$(cd "$(dirname "$cfg")" && pwd)"
  log="$dir/log.log"

  echo "[RUN ] $cfg"
  if (cd "$dir" && java $JAVA_OPTS -jar "$JAR" --options-file "$cfg" >"$log" 2>&1); then
    echo "[DONE] $cfg"
  else
    echo "[FAIL] $cfg (see $log)" >&2
    return 1
  fi
}

if [[ "${1:-}" == "--batch" ]]; then
  root="${2:?usage: $0 --batch <targets-dir> [jobs]}"
  max_jobs="${3:-8}"

  for dir in "$root"/*/; do
    [[ -d "$dir" ]] || continue
    name="$(basename "$dir")"

    # A `time` file means this target has already been analysed.
    if [[ -f "$dir/time" ]]; then
      echo "[SKIP] $name (already analysed)"
      continue
    fi

    analyse_one "$dir/config.yml" &

    while (($(jobs -r -p | wc -l) >= max_jobs)); do
      sleep 1
    done
  done

  wait
  echo "All targets processed."
else
  analyse_one "${1:?usage: $0 <config.yml> | $0 --batch <targets-dir> [jobs]}"
fi
