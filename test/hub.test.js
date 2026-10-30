const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, execFile } = require('child_process');
const { startHub } = require('../server');
const { Alerts } = require('../alerts');
const { quietHours, normalizeInventory } = require('../support');

const ROOT = path.join(__dirname, '..');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dm-test-'));
const PORT = 17000 + (process.pid % 2000);
const BASE = `http://127.0.0.1:${PORT}`;
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = await fn(); if (v) return v; await sleep(200); }
  throw new Error('timed out');
}

let hub, dataDir, admin, children = [], sandbox;
const json = (p, { key, method = 'GET', body } = {}) => fetch(BASE + p, {
  method, headers: { 'Content-Type': 'application/json', ...(key ? { Authorization: `Bearer ${key}` } : {}) }, body: body && JSON.stringify(body),
});
const report = (id, token, extra = {}) => json('/api/report', { method: 'POST', body: { id, token, hostname: id, platform: 'windows', cpu: {}, memory: {}, ...extra } });

test.before(async () => {
  dataDir = tmp();
  sandbox = tmp();
  hub = await startHub({ port: PORT, dataDir, rootDir: ROOT, bind: ['127.0.0.1'], strict: true, discovery: false });
  admin = hub.token;
});
test.after(() => {
  for (const c of children) { try { process.kill(-c.pid); } catch {} }
  hub.close();
  setTimeout(() => process.exit(0), 200);
});

test('loopback alone is not trusted', async () => {
  assert.equal((await json('/api/devices')).status, 401);
  assert.equal((await json('/api/support')).status, 401);
  assert.equal((await json('/support')).status, 401);
  assert.equal((await json('/api/devices', { key: admin })).status, 200);
});

test('info without the key does not reveal any key', async () => {
  const b = await (await json('/api/info')).json();
  assert.equal(b.token, undefined);
  assert.equal(b.joinKey, undefined);
});

test('pairing is off in strict mode', async () => {
  assert.equal((await json('/api/pair/code', { key: admin, method: 'POST' })).status, 404);
  assert.equal((await json('/api/pair', { method: 'POST', body: { code: '123456' } })).status, 403);
});

test('admin key cannot report and an unknown device cannot report', async () => {
  assert.equal((await report('dev-x', admin)).status, 401);
  assert.equal((await report('dev-x', 'nope')).status, 401);
});

test('join key only enrolls: no dashboard, and a rotated key stops working', async () => {
  const j = await (await json('/api/join', { key: admin })).json();
  assert.equal((await json('/api/devices', { key: j.key })).status, 401);
  assert.equal((await json('/api/enroll', { method: 'POST', body: { enroll: 'wrong', id: 'dev-a' } })).status, 403);
  const enrolled = await json('/api/enroll', { method: 'POST', body: { enroll: j.key, id: 'dev-a', hostname: 'A' } });
  assert.equal(enrolled.status, 200);
  const { key } = await enrolled.json();
  assert.notEqual(key, admin);
  assert.equal((await report('dev-a', key)).status, 200);
  assert.equal((await json('/api/devices', { key })).status, 401);
  const n = await (await json('/api/join/new', { key: admin, method: 'POST' })).json();
  assert.equal((await json('/api/enroll', { method: 'POST', body: { enroll: j.key, id: 'dev-z' } })).status, 403);
  assert.notEqual(n.key, j.key);
  const script = await (await json(`/install.sh?token=${n.key}`)).text();
  assert.ok(!script.includes(admin), 'installer must not carry the admin key');
  assert.ok(script.includes(n.key));
  assert.equal((await json(`/install.sh?token=${j.key}`)).status, 403);
});

test('one device key cannot report as another; keys are hashed at rest', async () => {
  const j = await (await json('/api/join', { key: admin })).json();
  const a = await (await json('/api/enroll', { method: 'POST', body: { enroll: j.key, id: 'dev-b' } })).json();
  const b = await (await json('/api/enroll', { method: 'POST', body: { enroll: j.key, id: 'dev-c' } })).json();
  assert.equal((await report('dev-c', a.key)).status, 401);
  assert.equal((await report('dev-c', b.key)).status, 200);
  const stored = fs.readFileSync(path.join(dataDir, 'device-keys.json'), 'utf8');
  assert.ok(!stored.includes(a.key));
  assert.equal(fs.statSync(path.join(dataDir, 'config.json')).mode & 0o077, 0);
});

test('actions need the admin key, the device opt-in, and a typed confirm', async () => {
  const j = await (await json('/api/join', { key: admin })).json();
  const { key } = await (await json('/api/enroll', { method: 'POST', body: { enroll: j.key, id: 'dev-act' } })).json();
  await report('dev-act', key);
  const act = (who, body) => json('/api/devices/dev-act/action', { key: who, method: 'POST', body });
  assert.equal((await act(undefined, { action: 'restart', confirm: 'dev-act' })).status, 401);
  assert.equal((await act(key, { action: 'restart', confirm: 'dev-act' })).status, 401);
  assert.equal((await act(admin, { action: 'restart', confirm: 'dev-act' })).status, 409);
  await report('dev-act', key, { actions: ['restart', 'script'], scripts: [{ name: 'flush-dns', sha: 'a'.repeat(64) }] });
  assert.equal((await act(admin, { action: 'restart' })).status, 400);
  assert.equal((await act(admin, { action: 'script', script: 'rm-everything' })).status, 400);
  assert.equal((await act(admin, { action: 'script', script: '__proto__' })).status, 400);
  assert.equal((await act(admin, { action: 'script', script: 'flush-dns' })).status, 409, 'hash mismatch is refused');
  assert.equal((await act(admin, { action: 'restart', confirm: 'dev-act' })).status, 200);
  const r = await (await report('dev-act', key, { actions: ['restart'] })).json();
  assert.equal(r.commands[0].action, 'restart');
  const again = await (await report('dev-act', key, { actions: ['restart'] })).json();
  assert.equal(again.commands, undefined, 'delivered once');
  assert.equal((await json('/api/result', { method: 'POST', body: { id: 'dev-c', token: 'x', cmd: r.commands[0].id } })).status, 401);
  assert.equal((await json('/api/result', { method: 'POST', body: { id: 'dev-act', token: key, cmd: 'ffffffffffff', ok: true } })).status, 404);
  assert.equal((await json('/api/result', { method: 'POST', body: { id: 'dev-act', token: key, cmd: r.commands[0].id, ok: true, message: 'ok' } })).status, 200);
  const audit = fs.readFileSync(path.join(dataDir, 'audit.jsonl'), 'utf8');
  for (const kind of ['requested', 'delivered', 'result', 'refused']) assert.ok(audit.includes(`"kind":"${kind}"`), kind);
  assert.ok(!audit.includes(admin) && !audit.includes(key), 'audit log has no keys');
});

test('address ranges for actions', () => {
  const sec = require('../security');
  assert.equal(sec.isTailnetOrLoopback('192.168.2.50'), false);
  assert.equal(sec.isTailnetOrLoopback('::ffff:172.17.0.2'), false);
  assert.equal(sec.isTailnetOrLoopback('100.102.39.102'), true);
  assert.equal(sec.isTailnetOrLoopback('100.128.0.1'), false);
});

const lanIp = Object.values(os.networkInterfaces()).flat().find(a => a.family === 'IPv4' && !a.internal && !a.address.startsWith('100.'))?.address;

test('over a real non-Tailscale address: strict hub refuses, LAN mode reports but actions stay off', { skip: !lanIp && 'no LAN address on this machine' }, async () => {
  const port = PORT + 1, url = `http://${lanIp}:${port}`;
  const strictHub = await startHub({ port, dataDir: tmp(), rootDir: ROOT, bind: [lanIp], strict: true, discovery: false });
  assert.equal((await fetch(`${url}/api/info`)).status, 403);
  strictHub.close();
  await sleep(100);
  const lanHub = await startHub({ port: port + 1, dataDir: tmp(), rootDir: ROOT, bind: [lanIp], strict: true, allowLan: true, discovery: false });
  const lan = `http://${lanIp}:${port + 1}`, auth = { Authorization: `Bearer ${lanHub.token}`, 'Content-Type': 'application/json' };
  const post = (p, body, headers = { 'Content-Type': 'application/json' }) => fetch(lan + p, { method: 'POST', headers, body: JSON.stringify(body) });
  const j = await (await fetch(`${lan}/api/join`, { headers: auth })).json();
  const { key } = await (await post('/api/enroll', { enroll: j.key, id: 'lan-pc' })).json();
  assert.equal((await post('/api/report', { id: 'lan-pc', token: key, hostname: 'lan-pc', platform: 'windows', cpu: {}, memory: {}, actions: ['restart'] })).status, 200);
  const act = await post('/api/devices/lan-pc/action', { action: 'restart', confirm: 'lan-pc' }, auth);
  assert.equal(act.status, 403);
  lanHub.close();
});

test('rebinding: a request addressed to another hostname is refused', async () => {
  const http = require('http');
  const status = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: PORT, path: '/api/info', headers: { Host: 'evil.example' } }, r => { r.resume(); resolve(r.statusCode); }).on('error', reject);
  });
  assert.equal(status, 421);
});

test('cross-site requests are refused', async () => {
  const cross = await fetch(BASE + '/api/join/new', { method: 'POST', headers: { Authorization: `Bearer ${admin}`, Origin: 'https://evil.example' } });
  assert.equal(cross.status, 403);
});

test('an expired join key is refused and replaced', () => {
  const { JoinKey } = require('../support');
  const config = { joinKey: 'a'.repeat(24), joinExpires: Date.now() - 1 };
  const j = new JoinKey(config, () => {});
  assert.equal(j.valid('a'.repeat(24)), false);
  const fresh = j.current();
  assert.notEqual(fresh.key, 'a'.repeat(24));
  assert.equal(j.valid(fresh.key), true);
});

test('inventory is cleaned and tied to the device key', async () => {
  const j = await (await json('/api/join', { key: admin })).json();
  const { key } = await (await json('/api/enroll', { method: 'POST', body: { enroll: j.key, id: 'dev-inv' } })).json();
  await report('dev-inv', key);
  const inv = { user: 'greg', rebootRequired: true, hw: { vendor: 'Dell', model: 'X' }, apps: [{ name: '<img src=x>', version: '1' }, { nope: 1 }], updates: { checked: true, count: 2, items: [{ title: 'KB1' }] } };
  assert.equal((await json('/api/inventory', { method: 'POST', body: { id: 'dev-inv', token: 'bad', inventory: inv } })).status, 401);
  assert.equal((await json('/api/inventory', { method: 'POST', body: { id: 'dev-inv', token: key, inventory: inv } })).status, 200);
  const got = await (await json('/api/devices/dev-inv/inventory', { key: admin })).json();
  assert.equal(got.apps.length, 1);
  assert.equal(got.updates.count, 2);
  assert.equal(got.rebootRequired, true);
  assert.equal(normalizeInventory('x'), null);
});

test('device fields are validated', async () => {
  const bad = await json('/api/devices/dev-inv', { key: admin, method: 'PATCH', body: { sshUser: 'x"; rm -rf /' } });
  assert.equal(bad.status, 400);
  const ok = await json('/api/devices/dev-inv', { key: admin, method: 'PATCH', body: { sshUser: 'greg', rustdeskId: '123 456 789' } });
  assert.equal((await ok.json()).rustdeskId, '123456789');
});

test('quiet hours', () => {
  const q = quietHours('18:00-08:00,weekends');
  assert.equal(q(new Date('2026-10-28T12:00:00').getTime()), false);
  assert.equal(q(new Date('2026-10-28T19:00:00').getTime()), true);
  assert.equal(q(new Date('2026-10-28T07:00:00').getTime()), true);
  assert.equal(q(new Date('2026-10-31T12:00:00').getTime()), true);
  assert.equal(quietHours('')(Date.now()), false);
});

test('alerts: offline, disk and temperature fire and reach the sink; quiet hours hold offline back', async () => {
  const dir = tmp(), seen = [];
  let quiet = false;
  const device = { id: 'p1', name: 'Greg', online: false, lastSeen: 0 };
  const a = new Alerts({ dataDir: dir, broadcast() {}, devices: () => [device], costToday: () => null, hubUrl: () => 'http://x', sink: ev => seen.push(ev), offlineQuiet: () => quiet, log() {} });
  device.lastSeen = Date.now() - 3600e3;
  quiet = true; a.tick();
  assert.equal(seen.length, 0);
  quiet = false; a.tick();
  assert.equal(seen.filter(e => e.type === 'offline' && e.state === 'firing').length, 1);
  a.tick();
  assert.equal(seen.filter(e => e.type === 'offline').length, 1, 'one alert, not one per tick');
  a.onReport('p1', { disks: [{ name: 'C:', total: 500e9, used: 480e9 }], cpu: { temp: 50 }, gpus: [] });
  assert.ok(seen.some(e => e.type === 'disk' && e.state === 'firing'));
  const tempRule = a.cfg.rules.find(r => r.type === 'cpuTemp');
  tempRule.minutes = 0;
  a.onReport('p1', { disks: [], cpu: { temp: 97 }, gpus: [] });
  assert.ok(seen.some(e => e.type === 'cpuTemp' && e.state === 'firing'));
  a.close();
});

function runShellAgent(script, env) {
  const c = spawn('/bin/bash', [script], { detached: true, stdio: 'ignore', env });
  children.push(c);
  return c;
}

test('real Linux installer + agent: enrolls, reports, runs a vetted script, posts inventory, cannot restart', async () => {
  const j = await (await json('/api/join', { key: admin })).json();
  const dir = path.join(sandbox, 'linux');
  const script = await (await json(`/install.sh?token=${j.key}&actions=1`)).text();
  const home = path.join(sandbox, 'home');
  fs.mkdirSync(home, { recursive: true });
  const out = await new Promise((resolve, reject) => execFile('/bin/bash', ['-c', script], { encoding: 'utf8', env: { ...process.env, HOME: home, DM_NO_SERVICE: '1', DM_INSTALL_DIR: dir } }, (e, stdout) => (e ? reject(e) : resolve(stdout))));
  assert.match(out, /service setup skipped/);
  const cfg = fs.readFileSync(path.join(dir, 'config'), 'utf8');
  assert.match(cfg, /ACTIONS='restart script'/);
  assert.ok(!cfg.includes(admin));
  assert.equal(fs.statSync(path.join(dir, 'config')).mode & 0o077, 0);
  assert.ok(fs.existsSync(path.join(dir, 'scripts/network-check.sh')));
  runShellAgent(path.join(dir, 'agent.sh'), { ...process.env, HOME: home, INTERVAL: '1' });
  const me = await until(async () => (await (await json('/api/support', { key: admin })).json()).devices.find(d => d.platform === 'linux' && d.online));
  assert.ok(me.scripts.every(s => s.vetted) && me.scripts.length === 2);
  const inv = await until(async () => (await (await json('/api/support', { key: admin })).json()).devices.find(d => d.id === me.id && d.inventory));
  assert.ok(inv.inventory.apps > 0);
  const send = await json(`/api/devices/${me.id}/action`, { key: admin, method: 'POST', body: { action: 'script', script: 'disk-report' } });
  assert.equal(send.status, 200);
  const res = await until(async () => (await (await json('/api/support', { key: admin })).json()).results.find(r => r.device === me.id && r.script === 'disk-report'));
  assert.equal(res.ok, true, res.message);
  assert.match(res.output, /Largest folders/);
  const restart = await json(`/api/devices/${me.id}/action`, { key: admin, method: 'POST', body: { action: 'restart', confirm: me.name } });
  assert.equal(restart.status, 200);
  const rr = await until(async () => (await (await json('/api/support', { key: admin })).json()).results.find(r => r.device === me.id && r.action === 'restart'));
  assert.equal(rr.ok, false, 'the Linux agent has no restart code');
  for (const c of children.splice(0)) { try { process.kill(-c.pid); } catch {} }
});

test('real macOS agent on mock tools: reports and restart goes through osascript', async () => {
  const j = await (await json('/api/join', { key: admin })).json();
  const dir = path.join(sandbox, 'mac');
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  const mocks = path.join(sandbox, 'macbin');
  fs.mkdirSync(mocks, { recursive: true });
  for (const f of fs.readdirSync(path.join(ROOT, 'build/test/macos/bin'))) if (f !== 'curl' && f !== 'awk') fs.copyFileSync(path.join(ROOT, 'build/test/macos/bin', f), path.join(mocks, f));
  for (const f of fs.readdirSync(mocks)) fs.chmodSync(path.join(mocks, f), 0o755);
  const flag = path.join(sandbox, 'osascript-called');
  fs.writeFileSync(path.join(mocks, 'osascript'), `#!/bin/bash\necho "$*" > "${flag}"\n`, { mode: 0o755 });
  for (const f of ['agent-macos.sh', 'agent-support.sh', 'inventory-macos.sh']) fs.copyFileSync(path.join(ROOT, 'agent', f), path.join(dir, f));
  fs.copyFileSync(path.join(ROOT, 'agent/scripts/macos/disk-report.sh'), path.join(dir, 'scripts/disk-report.sh'));
  const { key } = await (await json('/api/enroll', { method: 'POST', body: { enroll: j.key, id: 'mac-mock' } })).json();
  fs.writeFileSync(path.join(dir, 'config'), `HUB='${BASE}'\nTOKEN='${key}'\nACTIONS='restart script'\n`);
  const body = fs.readFileSync(path.join(dir, 'agent-macos.sh'), 'utf8').replace(/^ID=.*$/m, 'ID=mac-mock');
  fs.writeFileSync(path.join(dir, 'agent-macos.sh'), body);
  runShellAgent(path.join(dir, 'agent-macos.sh'), { ...process.env, PATH: `${mocks}:${process.env.PATH}`, INTERVAL: '1', INVENTORY_EVERY: '999999999' });
  const me = await until(async () => (await (await json('/api/support', { key: admin })).json()).devices.find(d => d.id === 'mac-mock' && d.online && d.latest?.actions?.includes('restart')));
  assert.equal(me.platform, 'macos');
  const send = await json('/api/devices/mac-mock/action', { key: admin, method: 'POST', body: { action: 'restart', confirm: me.name } });
  assert.equal(send.status, 200);
  await until(() => fs.existsSync(flag));
  assert.match(fs.readFileSync(flag, 'utf8'), /System Events/);
  for (const c of children.splice(0)) { try { process.kill(-c.pid); } catch {} }
});
