#!/bin/sh
set -eu
VPS_MANAGER_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export VPS_MANAGER_ROOT
. "$VPS_MANAGER_ROOT/lib/common.sh"
vps_manager_exec diagnose "$@"
