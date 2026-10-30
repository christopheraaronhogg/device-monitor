#!/bin/bash
# desc: Network check: addresses, DNS, internet and Tailscale status
echo "== Addresses"; (ip -4 -br addr 2>/dev/null || ifconfig 2>/dev/null | grep 'inet ')
echo; echo "== Internet"; ping -c 2 1.1.1.1 2>&1 | tail -2
echo; echo "== DNS"; (getent hosts cloudflare.com 2>/dev/null || dscacheutil -q host -a name cloudflare.com 2>/dev/null) | head -4
echo; echo "== Tailscale"
for t in tailscale /Applications/Tailscale.app/Contents/MacOS/Tailscale; do
  command -v "$t" >/dev/null 2>&1 && { "$t" status 2>&1 | head -12; break; }
done
