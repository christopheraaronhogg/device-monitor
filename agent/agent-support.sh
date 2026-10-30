# Shared by agent.sh and agent-macos.sh. Written for bash 3.2 (macOS).
AGENT_VERSION="1.3.0"
ACTIONS="${ACTIONS:-}"
INVENTORY_EVERY="${INVENTORY_EVERY:-21600}"
SCRIPT_TIMEOUT="${SCRIPT_TIMEOUT:-120}"
DM_INV_LAST=0

dm_sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

dm_enabled() {
  case " $ACTIONS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

dm_extra_json() {
  local actions="" scripts="" a f name
  for a in $ACTIONS; do
    case "$a" in restart|script) actions="$actions${actions:+,}\"$a\"" ;; esac
  done
  if dm_enabled script && [ -d "$DIR/scripts" ]; then
    for f in "$DIR"/scripts/*.sh; do
      [ -f "$f" ] || continue
      name="$(basename "$f" .sh)"
      scripts="$scripts${scripts:+,}{\"name\":\"$name\",\"sha\":\"$(dm_sha "$f")\"}"
    done
  fi
  printf '"features":[%s],"actions":[%s],"scripts":[%s]' "$([ -n "$actions" ] && echo '"actions"')" "$actions" "$scripts"
}
DM_EXTRA="$(dm_extra_json)"

dm_json_text() {
  printf '%s' "$1" | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177' | tr -d '\r' | tr '\t' ' ' \
    | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | awk '{ printf "%s\\n", $0 }'
}

dm_post_result() {
  local cmd="$1" ok="$2" message="$3" output="$4"
  printf '{"id":"%s","token":"%s","cmd":"%s","ok":%s,"message":"%s","output":"%s"}' \
    "$ID" "$TOKEN" "$cmd" "$ok" "$(dm_json_text "$message" | sed 's/\\n$//')" "$(dm_json_text "$(printf '%s' "$output" | tail -c 15000)")" \
    | curl -fsS -m 10 -X POST -H 'Content-Type: application/json' --data-binary @- "$HUB/api/result" >/dev/null 2>&1
}

dm_with_timeout() {
  if command -v timeout >/dev/null 2>&1; then timeout "$SCRIPT_TIMEOUT" "$@"; else perl -e 'alarm shift; exec @ARGV' "$SCRIPT_TIMEOUT" "$@"; fi
}

dm_run_script() {
  local cmd="$1" name="$2" f out rc
  case "$name" in *[!a-z0-9-]*|"") dm_post_result "$cmd" false "Bad script name." ""; return ;; esac
  f="$DIR/scripts/$name.sh"
  [ -f "$f" ] || { dm_post_result "$cmd" false "Script not installed on this device." ""; return; }
  ( out="$(dm_with_timeout /bin/bash "$f" 2>&1)"; rc=$?
    if [ $rc -eq 0 ]; then dm_post_result "$cmd" true "Finished." "$out"; else dm_post_result "$cmd" false "Exit code $rc." "$out"; fi ) &
}

dm_run_commands() {
  local cmds line cid action script
  cmds="$(printf '%s' "$1" | sed -n 's/.*"cmds":"\([^"]*\)".*/\1/p')"
  [ -n "$cmds" ] || return 0
  printf '%s\n' "$cmds" | tr ';' '\n' | while read -r cid action script; do
    case "$cid" in *[!a-f0-9]*|"") continue ;; esac
    case "$action" in
      restart)
        if dm_enabled restart && command -v dm_restart >/dev/null 2>&1; then
          if out="$(dm_restart 2>&1)"; then dm_post_result "$cid" true "Restart started." "$out"; else dm_post_result "$cid" false "Restart failed." "$out"; fi
        else dm_post_result "$cid" false "Restart is off on this device." ""; fi ;;
      script)
        if dm_enabled script; then dm_run_script "$cid" "$script"; else dm_post_result "$cid" false "Scripts are off on this device." ""; fi ;;
      *) dm_post_result "$cid" false "Unknown action." "" ;;
    esac
  done
}

dm_send_report() {
  local reply
  reply="$(printf '%s' "$1" | curl -fsS -m 5 -X POST -H 'Content-Type: application/json' --data-binary @- "$HUB/api/report" 2>/dev/null)"
  dm_run_commands "$reply"
}

dm_inventory_tick() {
  local now f
  now="$(date +%s)"
  [ $((now - DM_INV_LAST)) -ge "$INVENTORY_EVERY" ] || return 0
  DM_INV_LAST="$now"
  f="$DIR/$1"
  [ -f "$f" ] || return 0
  ( HUB="$HUB" TOKEN="$TOKEN" ID="$ID" nice -n 19 /bin/bash "$f" >/dev/null 2>&1 ) &
}
