#!/bin/sh
# Local checkout wrapper; without --execute the Python tool performs no system changes.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /usr/bin/python3 -B -E -s "$project_dir/tools/installer.py" "$@"
