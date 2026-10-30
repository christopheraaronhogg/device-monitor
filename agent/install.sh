#!/usr/bin/env bash
# Device Monitor installer (Linux and macOS). Served by the hub with its values filled in.
set -e
HUB='__HUB__'; ENROLL='__ENROLL__'; ACTIONS='__ACTIONS__'

enroll() {
  local reply key
  reply="$(printf '{"enroll":"%s","id":"%s","hostname":"%s"}' "$ENROLL" "$1" "$2" | curl -fsS -m 15 -X POST -H 'Content-Type: application/json' --data-binary @- "$HUB/api/enroll")"
  key="$(printf '%s' "$reply" | sed -n 's/.*"key":"\([a-f0-9]*\)".*/\1/p')"
  [ -n "$key" ] || { echo "The hub refused this device: $reply" >&2; exit 1; }
  printf '%s' "$key"
}

fetch_agent() {
  local dir="$1" platform="$2" scripts="$3" agent="$4" inv="$5" s
  mkdir -p "$dir/scripts"
  for s in "$agent" agent-support.sh "$inv"; do curl -fsSL "$HUB/$s" -o "$dir/$s"; done
  chmod +x "$dir/$agent"
  rm -f "$dir"/scripts/*.sh
  if [ -n "$ACTIONS" ]; then
    for s in $scripts; do curl -fsSL "$HUB/agent/scripts/$platform/$s" -o "$dir/scripts/$s.sh"; done
  fi
}

write_config() {
  ( umask 077; printf "HUB='%s'\nTOKEN='%s'\nACTIONS='%s'\n" "$HUB" "$2" "$ACTIONS" > "$1/config" )
}

if [ "$(uname -s)" = "Darwin" ]; then
  DIR="$HOME/Library/Application Support/DeviceMonitorAgent"
  PLIST="$HOME/Library/LaunchAgents/com.devicemonitor.agent.plist"
  mkdir -p "$DIR" "$HOME/Library/LaunchAgents"
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  ID="$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/ { print $4; exit }')"
  [ -n "$ID" ] || ID="$(hostname)"
  NAME="$(scutil --get ComputerName 2>/dev/null || hostname -s)"
  KEY="$(enroll "$ID" "$NAME")"
  fetch_agent "$DIR" macos '__SCRIPTS_MACOS__' agent-macos.sh inventory-macos.sh
  write_config "$DIR" "$KEY"
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.devicemonitor.agent</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$DIR/agent-macos.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
PLIST
  [ -n "$DM_NO_SERVICE" ] || launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null || launchctl load -w "$PLIST"
  echo "Device Monitor agent for $NAME -> $HUB (LaunchAgent com.devicemonitor.agent)."
  if ! command -v smctemp >/dev/null 2>&1 && [ ! -x /opt/homebrew/bin/smctemp ] && [ ! -x /usr/local/bin/smctemp ]; then
    echo "Temperatures are off until you run: brew install smctemp  (takes effect after the next login)."
  fi
  [ -z "$ACTIONS" ] || echo "Remote restart: macOS asks to allow Automation for bash the first time. Approve it once at the Mac."
  echo "Uninstall: curl -fsSL $HUB/uninstall.sh | bash"
  exit 0
fi

DIR="${DM_INSTALL_DIR:-$HOME/.local/share/device-monitor}"
mkdir -p "$DIR"
ID="$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || hostname)"
KEY="$(enroll "$ID" "$(hostname)")"
pkill -f "$DIR/agent.sh" 2>/dev/null || true
fetch_agent "$DIR" linux '__SCRIPTS_LINUX__' agent.sh inventory-linux.sh
write_config "$DIR" "$KEY"

if [ -n "$DM_NO_SERVICE" ]; then
  echo "Files written to $DIR; service setup skipped."
elif command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/device-monitor.service" <<UNIT
[Unit]
Description=Device Monitor agent
After=network-online.target
[Service]
ExecStart=/usr/bin/env bash $DIR/agent.sh
Restart=always
RestartSec=5
Nice=10
[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload
  systemctl --user enable --now device-monitor.service
  loginctl enable-linger "$USER" 2>/dev/null || true
  echo "Installed as systemd user service 'device-monitor'."
else
  (crontab -l 2>/dev/null | grep -v device-monitor; echo "@reboot nohup bash $DIR/agent.sh >/dev/null 2>&1 &") | crontab -
  nohup bash "$DIR/agent.sh" >/dev/null 2>&1 &
  echo "Installed via crontab @reboot."
fi
echo "Device Monitor agent for $(hostname) -> $HUB. Uninstall: curl -fsSL $HUB/uninstall.sh | bash"
