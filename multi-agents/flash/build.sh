#!/bin/bash
# Build the Stage-1 taint analysis container. Running the analysis directly with
# a local JDK 17 does not need this image; see run.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
docker build -t gadgethunter-flash .
echo
echo "Built gadgethunter-flash. Analyse a mounted target directory with:"
echo "  docker run --rm -v /path/to/targets:/targets gadgethunter-flash --batch /targets"
