// Options for the headless hub, from the environment. Defaults are the locked-down ones.
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { quietHours } = require('./support');

const run = (cmd, args) => new Promise(resolve => execFile(cmd, args, { timeout: 8000 }, (e, out) => resolve(e ? '' : String(out))));

async function resolveBind(spec) {
  const out = [];
  for (const part of spec.split(',').map(s => s.trim()).filter(Boolean)) {
    if (part !== 'tailscale') { out.push(part); continue; }
    const ip = (await run('tailscale', ['ip', '-4'])).trim().split('\n')[0];
    if (!ip) throw Object.assign(new Error('Tailscale has no IPv4 address yet.'), { code: 'EADDRNOTAVAIL' });
    out.push(ip);
  }
  return out;
}

function localMachineId() {
  for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
    try { return fs.readFileSync(f, 'utf8').trim(); } catch {}
  }
  return os.hostname();
}

function alertSink(dir) {
  if (!dir) return null;
  return ev => {
    fs.mkdirSync(dir, { recursive: true });
    const stamp = new Date(ev.t).toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
    const kind = String(ev.type || 'test').replace(/[^a-zA-Z]/g, '').toLowerCase();
    const file = path.join(dir, `${stamp}-device-monitor-${kind}-${ev.state}-${ev.id}.md`);
    fs.writeFileSync(file, `# ${ev.title}\n\n${ev.message}\n\nDevice: ${ev.deviceName || '-'}\nState: ${ev.state}\nTime: ${new Date(ev.t).toString()}\n`);
    execFile('notify-send', ['-a', 'Device Monitor', '-u', ev.state === 'firing' ? 'critical' : 'normal', ev.title, ev.message], () => {});
  };
}

async function headlessOptions(env) {
  return {
    dataDir: env.DM_DATA_DIR || undefined,
    bind: await resolveBind(env.DM_BIND || 'tailscale,127.0.0.1'),
    strict: env.DM_STRICT !== '0',
    allowLan: env.DM_ALLOW_LAN === '1',
    discovery: env.DM_DISCOVERY === '1',
    alertSink: alertSink(env.DM_ALERTS_DIR),
    offlineQuiet: quietHours(env.DM_OFFLINE_QUIET),
  };
}

module.exports = { headlessOptions, localMachineId };
