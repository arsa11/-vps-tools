#!/bin/sh
# Shared shell entry point. The transactional core lives in vpsmanager/.
vps_manager_exec() {
    : "${VPS_MANAGER_ROOT:?VPS_MANAGER_ROOT is required}"
    exec python3 "$VPS_MANAGER_ROOT/vps_manager.py" "$@"
}
