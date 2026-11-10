#!/usr/bin/env bash
# Ubuntu Netplan: safely select the preferred outgoing IPv4 from already assigned addresses.
set -Eeuo pipefail
export LC_ALL=C
[[ $EUID -eq 0 ]] || { echo 'Run: sudo bash ip-switcher.sh'; exit 1; }
for cmd in ip python3 netplan cp mktemp; do command -v "$cmd" >/dev/null || { echo "Missing: $cmd"; exit 1; }; done
IFACE=${IFACE:-$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++)if($i=="dev")print $(i+1)}')}
[[ -n "$IFACE" ]] || { echo 'No default IPv4 interface'; exit 1; }
mapfile -t IPS < <(ip -o -4 addr show dev "$IFACE" scope global | awk '{split($4,a,"/"); print a[1]}')
((${#IPS[@]})) || { echo "No IPv4 on $IFACE"; exit 1; }
GATEWAY=$(ip -4 route show default dev "$IFACE" | awk 'NR==1 {for(i=1;i<=NF;i++)if($i=="via")print $(i+1)}')
[[ -n "$GATEWAY" ]] || { echo 'Default route without gateway is unsupported'; exit 1; }
echo "Interface: $IFACE | Gateway: $GATEWAY"
echo "Existing IPv4 (do not remove the gateway's original subnet address):"
for i in "${!IPS[@]}"; do printf ' %d) %s\n' "$((i+1))" "${IPS[$i]}"; done
echo ' 0) Exit'
read -rp 'Choose preferred outgoing IPv4: ' PICK
[[ "$PICK" =~ ^[0-9]+$ ]] && ((PICK>=1 && PICK<=${#IPS[@]})) || { echo 'Cancelled / invalid choice'; exit 1; }
TARGET=${IPS[$((PICK-1))]}
echo "Selected: $TARGET"
read -rp 'Apply to Netplan permanently? [y/N]: ' YES
[[ "$YES" =~ ^[yY]$ ]] || { echo 'No changes made'; exit 0; }
# Identify one and only one Netplan YAML containing the default IPv4 gateway route.
mapfile -t FILES < <(python3 - "$GATEWAY" <<'PY'
import pathlib,re,sys
gw=re.escape(sys.argv[1])
for p in sorted(pathlib.Path('/etc/netplan').glob('*.yaml')):
    s=p.read_text()
    if re.search(r'(?m)^\s+via:\s*'+gw+r'\s*(?:#.*)?$',s):print(p)
PY
)
((${#FILES[@]}==1)) || { echo "Expected one Netplan file for gateway $GATEWAY; found ${#FILES[@]}. No changes."; exit 1; }
FILE=${FILES[0]}
BACKUP="${FILE}.backup-ip-switch-$(date +%Y%m%d-%H%M%S)"
cp -a -- "$FILE" "$BACKUP"
echo "Backup: $BACKUP"
# Strictly replace only the IPv4 default route source. All IP addresses, DNS, and IPv6 remain intact.
if ! python3 - "$FILE" "$GATEWAY" "$TARGET" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]); gw=sys.argv[2]; target=sys.argv[3]
s=p.read_text()
# Only simple route blocks: '- to: default', 'via: gateway', optional 'from:' and other properties.
lines=s.splitlines(keepends=True)
matches=[]
for i,line in enumerate(lines):
    m=re.match(r'^(\s*)-\s*to:\s*default\s*(?:#.*)?\n?$',line)
    if not m:continue
    indent=len(m.group(1))
    end=i+1
    while end<len(lines):
        l=lines[end]
        if l.strip() and len(l)-len(l.lstrip())<=indent:break
        end+=1
    block=''.join(lines[i:end])
    if re.search(r'(?m)^\s+via:\s*'+re.escape(gw)+r'\s*(?:#.*)?$',block):
        matches.append((i,end,indent))
if len(matches)!=1:sys.exit('Could not uniquely identify IPv4 default route')
i,end,indent=matches[0]
block=lines[i:end]
# Reject more complex route definitions rather than risk changing them incorrectly.
if any(re.match(r'^\s+(?:table|on-link|type|scope|metric|mtu|congestion-window|advertised-receive-window):',x) for x in block):
    sys.exit('Complex route configuration: refusing automatic edit')
existing=[j for j,l in enumerate(block) if re.match(r'^\s+from:',l)]
if len(existing)>1:sys.exit('Multiple from entries')
if existing:
    j=existing[0]; lead=re.match(r'^(\s*)',block[j]).group(1)
    block[j]=f'{lead}from: {target}\n'
else:
    via_line=next(j for j,l in enumerate(block) if re.match(r'^\s+via:',l))
    lead=re.match(r'^(\s*)',block[via_line]).group(1)
    block.insert(via_line+1,f'{lead}from: {target}\n')
lines[i:end]=block
p.write_text(''.join(lines))
PY
then
  cp -a -- "$BACKUP" "$FILE"; echo 'Restored original Netplan file'; exit 1
fi
if ! netplan generate; then
  cp -a -- "$BACKUP" "$FILE"; netplan generate || true
  echo 'Netplan invalid: restored backup'; exit 1
fi
echo
printf 'WARNING: netplan try may interrupt SSH. Use provider web console if possible.\n'
echo 'You must confirm within 120 seconds; otherwise Netplan attempts to revert.'
read -rp 'Start netplan try now? [y/N]: ' APPLY
if [[ "$APPLY" != [yY] ]]; then
  cp -a -- "$BACKUP" "$FILE"; netplan generate || true
  echo 'Cancelled. Original configuration restored.'; exit 0
fi
if ! netplan try --timeout 120; then
  cp -a -- "$BACKUP" "$FILE"
  netplan generate || true
  echo 'Netplan try failed; original YAML restored. Check active routes.'
  exit 1
fi
echo '=== Active route ==='
ip -4 route get 1.1.1.1 || true
echo '=== External IPv4 ==='
curl -4 -m 8 -fsS https://api.ipify.org || true
echo
echo "Done. Backup: $BACKUP"
