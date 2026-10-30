#!/usr/bin/env bash
# desc: posts OS, packages and pending updates to the hub
export LC_ALL=C
jq_text() { printf '%s' "$1" | tr -d '"\\' | tr -d '[:cntrl:]'; }
APPS=""; UPDATES=""; COUNT=0; CHECKED=false
if command -v pacman >/dev/null 2>&1; then
  APPS="$(pacman -Qe 2>/dev/null | awk '{ gsub(/["\\]/, ""); printf "%s{\"name\":\"%s\",\"version\":\"%s\"}", (n++ ? "," : ""), $1, $2 }')"
  if command -v checkupdates >/dev/null 2>&1; then
    OUT="$(checkupdates 2>/dev/null)"; rc=$?
    if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
      CHECKED=true
      COUNT="$(printf '%s' "$OUT" | grep -c .)"
      UPDATES="$(printf '%s\n' "$OUT" | head -100 | awk 'NF { gsub(/["\\]/, ""); printf "%s{\"title\":\"%s\"}", (n++ ? "," : ""), $0 }')"
    fi
  fi
elif command -v dpkg-query >/dev/null 2>&1; then
  APPS="$(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | awk '{ gsub(/["\\]/, ""); printf "%s{\"name\":\"%s\",\"version\":\"%s\"}", (n++ ? "," : ""), $1, $2 }')"
  OUT="$(apt list --upgradable 2>/dev/null | grep upgradable)"
  CHECKED=true
  COUNT="$(printf '%s' "$OUT" | grep -c .)"
  UPDATES="$(printf '%s\n' "$OUT" | head -100 | awk 'NF { gsub(/["\\]/, ""); printf "%s{\"title\":\"%s\"}", (n++ ? "," : ""), $1 }')"
fi
REBOOT=false
[ -f /var/run/reboot-required ] && REBOOT=true
[ -d "/usr/lib/modules/$(uname -r)" ] || [ -d "/lib/modules/$(uname -r)" ] || REBOOT=true
VENDOR="$(jq_text "$(cat /sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null)")"
MODEL="$(jq_text "$(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null)")"
BODY="$(printf '{"id":"%s","token":"%s","inventory":{"user":"%s","rebootRequired":%s,"hw":{"vendor":"%s","model":"%s"},"apps":[%s],"updates":{"checked":%s,"count":%s,"items":[%s]}}}' \
  "$ID" "$TOKEN" "$(jq_text "$(id -un)")" "$REBOOT" "$VENDOR" "$MODEL" "$APPS" "$CHECKED" "$COUNT" "$UPDATES" \
 )"
try=0
while [ $try -lt 10 ]; do
  printf '%s' "$BODY" | curl -fsS -m 30 -X POST -H 'Content-Type: application/json' --data-binary @- "$HUB/api/inventory" >/dev/null 2>&1 && break
  try=$((try + 1)); sleep 60
done
