#!/bin/bash
# desc: posts macOS version, apps and pending updates to the hub
export LC_ALL=C
export PATH="$PATH:/usr/bin:/bin:/usr/sbin:/sbin"
clean() { printf '%s' "$1" | tr -d '"\\' | tr -d '[:cntrl:]'; }
APPS=""
for app in /Applications/*.app /Applications/Utilities/*.app; do
  [ -f "$app/Contents/Info.plist" ] || continue
  V="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist" 2>/dev/null)"
  APPS="$APPS${APPS:+,}{\"name\":\"$(clean "$(basename "$app" .app)")\",\"version\":\"$(clean "$V")\"}"
done
SU="$(softwareupdate -l 2>&1)"; rc=$?
CHECKED=false; COUNT=0; ITEMS=""; ERR=""
if [ $rc -eq 0 ]; then
  CHECKED=true
  ITEMS="$(printf '%s\n' "$SU" | awk -F'Title: ' '/Title: /{ split($2, a, ","); gsub(/["\\]/, "", a[1]); printf "%s{\"title\":\"%s\"}", (n++ ? "," : ""), a[1] }')"
  COUNT="$(printf '%s\n' "$SU" | grep -c 'Title: ')"
else
  ERR="$(clean "$(printf '%s' "$SU" | tail -1)")"
fi
HW="$(system_profiler SPHardwareDataType 2>/dev/null)"
MODEL="$(clean "$(printf '%s\n' "$HW" | awk -F': ' '/Model Name/ { print $2; exit }')")"
SERIAL="$(clean "$(printf '%s\n' "$HW" | awk -F': ' '/Serial Number/ { print $2; exit }')")"
BODY="$(printf '{"id":"%s","token":"%s","inventory":{"user":"%s","rebootRequired":null,"hw":{"vendor":"Apple","model":"%s","serial":"%s"},"apps":[%s],"updates":{"checked":%s,"count":%s,"items":[%s],"error":"%s"}}}' \
  "$ID" "$TOKEN" "$(clean "$(id -un)")" "$MODEL" "$SERIAL" "$APPS" "$CHECKED" "$COUNT" "$ITEMS" "$ERR" \
 )"
try=0
while [ $try -lt 10 ]; do
  printf '%s' "$BODY" | curl -fsS -m 30 -X POST -H 'Content-Type: application/json' --data-binary @- "$HUB/api/inventory" >/dev/null 2>&1 && break
  try=$((try + 1)); sleep 60
done
