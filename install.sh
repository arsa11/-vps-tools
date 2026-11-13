#!/bin/sh
set -eu
command -v python3 >/dev/null 2>&1 || { echo 'Нужен Python 3: apt-get install python3' >&2; exit 1; }
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$DIR/vps_manager.py" install-local
