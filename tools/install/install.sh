#!/bin/sh
# Local, independently authored bootstrap. No download, remote execution or hooks.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'Python 3.10+ is required; no packages were installed.' >&2; exit 2; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
    printf '%s\n' 'Python 3.10+ is required; no packages were installed.' >&2
    exit 2
}
exec python3 "$HERE/vpctl.py" "$@"
