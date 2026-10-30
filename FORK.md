# What this fork changes

The upstream app is built for one person's own machines, and one shared token unlocks everything. This fork adds remote actions, so it separates who can do what.

## Keys

| Key | Who holds it | What it can do |
|---|---|---|
| Admin key | You, via `device-monitor-hub link` | Dashboard, support page, remote actions |
| Join key | Whoever runs the install command. Expires after 7 days | Add a device. Nothing else |
| Device key | One agent. Only a hash is kept on the hub | Report for that one device |

## Security rules on the headless hub

- It listens on the Tailscale address and loopback only. Set `DM_BIND` to change that.
- Being on the hub machine grants nothing. Every API call needs a key.
- Remote actions travel only over Tailscale. In LAN mode (`DM_ALLOW_LAN=1`) traffic is plain HTTP, so actions are refused.
- **Actions are opt-in per PC**, chosen at install with `&actions=1`.
- **Scripts live on the PC.** The hub can only ask for a script by name. It refuses a script whose hash doesn't match its own vetted copy, and the agent only runs what was installed with it. There is no path for the hub to send code.
- **There is no web shell.** A shell through the hub would undo the rule above. The support page gives you `ssh` and RustDesk links instead.
- Restart needs the device's name typed to confirm. Windows PCs get a 60-second warning, cancelled with `shutdown /a`.
- The Linux agent has no restart code at all.
- Every request, delivery, result and refusal goes in `audit.jsonl` in the hub's data folder.

**What this doesn't protect against:** someone with the admin key, or control of the hub machine, can restart enrolled PCs and run the vetted scripts. They can't run anything else through the hub.

## Added features

- **Support page** at `/support`: online state, temperature, fullest disk, updates, restart-needed, software list, script results, audit log.
- **Inventory** every 6 hours: installed software, pending updates, reboot-required, model and serial.
- **Alerts** for offline, disk over 90%, and high temperature. Upstream's ntfy and webhook channels still work. `DM_ALERTS_DIR` also writes a file per alert and fires notify-send. `DM_OFFLINE_QUIET=18:00-08:00,weekends` holds back offline alerts out of hours.
- **Quieter agents:** they report every 5 seconds instead of 2, and keys are no longer visible in `ps`.

## Hub commands

```
device-monitor-hub link          # dashboard link; treat it like a password
device-monitor-hub join [--new]  # install commands; --new replaces the join key
device-monitor-hub status
device-monitor-hub test-alert
device-monitor-hub rotate-admin
```

## Install the hub (Linux, systemd user service)

```
cp deploy/device-monitor-hub.service ~/.config/systemd/user/   # adjust WorkingDirectory to your clone
ln -s "$PWD/bin/device-monitor-hub" ~/.local/bin/device-monitor-hub
node deploy/fetch-windows-tools.js      # hash-pinned LibreHardwareMonitor + PawnIO, served to Windows installs
systemctl --user daemon-reload && systemctl --user enable --now device-monitor-hub
```

## Tests

`npm test` runs the auth rules, the alert rules, and the real shell agents against a real hub. The macOS agent runs on mock tools. PowerShell isn't covered by the tests.

## License

Upstream declares MIT in `package.json`, but ships no LICENSE file or copyright line, and GitHub detects no license. This fork's changes are offered under the same MIT terms. Ask upstream to add a LICENSE before relying on this beyond internal use.
