// Tech-support additions to the hub: per-device keys, join key, inventory, vetted scripts, audit log.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { readJson, writeJson } = require('./safe-json');
const sec = require('./security');

const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const newKey = () => crypto.randomBytes(24).toString('hex');
const JOIN_MS = 7 * 86400e3;
const SCRIPT_NAME_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const SCRIPT_DIRS = { windows: '.ps1', macos: '.sh', linux: '.sh' };

class DeviceKeys {
  constructor(file) {
    this.file = file;
    this.keys = Object.assign(Object.create(null), readJson(file, {}));
  }
  issue(id) {
    const key = newKey();
    this.keys[id] = sha256(key);
    writeJson(this.file, this.keys);
    fs.chmodSync(this.file, 0o600);
    return key;
  }
  check(id, key) {
    return typeof key === 'string' && sec.isValidId(id) && !!this.keys[id] && sec.safeEqual(sha256(key), this.keys[id]);
  }
  remove(id) {
    delete this.keys[id];
    writeJson(this.file, this.keys);
  }
}

class JoinKey {
  constructor(config, save) { Object.assign(this, { config, save }); }
  valid(key) { return !!this.config.joinKey && Date.now() < (this.config.joinExpires || 0) && sec.safeEqual(key, this.config.joinKey); }
  current() {
    if (!this.config.joinKey || Date.now() >= (this.config.joinExpires || 0)) return this.rotate();
    return { key: this.config.joinKey, expires: this.config.joinExpires };
  }
  rotate() {
    this.config.joinKey = crypto.randomBytes(12).toString('hex');
    this.config.joinExpires = Date.now() + JOIN_MS;
    this.save();
    return { key: this.config.joinKey, expires: this.config.joinExpires };
  }
}

class Audit {
  constructor(file, limit = 500) {
    this.file = file;
    this.limit = limit;
    try {
      this.entries = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).slice(-limit).map(l => JSON.parse(l));
    } catch { this.entries = []; }
  }
  add(entry) {
    const e = { t: Date.now(), ...entry };
    this.entries.push(e);
    if (this.entries.length > this.limit) this.entries.shift();
    fs.appendFileSync(this.file, JSON.stringify(e) + '\n', { mode: 0o600 });
    return e;
  }
  recent(n = 100) { return this.entries.slice(-n).reverse(); }
}

class InventoryStore {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
  }
  file(id) { return path.join(this.dir, id + '.json'); }
  save(id, inv) { writeJson(this.file(id), inv, 0); }
  get(id) { return readJson(this.file(id), null); }
  remove(id) { for (const f of [this.file(id), this.file(id) + '.bak']) fs.rmSync(f, { force: true }); }
  summary(id) {
    const v = this.get(id);
    if (!v) return null;
    return { at: v.at, apps: v.apps.length, updates: v.updates.count, updatesChecked: v.updates.checked, rebootRequired: v.rebootRequired, user: v.user, hw: v.hw };
  }
}

function vettedScripts(agentDir) {
  const out = { windows: {}, macos: {}, linux: {} };
  for (const [platform, ext] of Object.entries(SCRIPT_DIRS)) {
    const dir = path.join(agentDir, 'scripts', platform);
    let files = [];
    try { files = fs.readdirSync(dir); } catch {}
    for (const f of files) {
      const name = f.slice(0, -ext.length);
      if (!f.endsWith(ext) || !SCRIPT_NAME_RE.test(name)) continue;
      const data = fs.readFileSync(path.join(dir, f));
      const desc = data.toString('utf8').match(/^# desc: (.+)$/m);
      out[platform][name] = { file: path.join(dir, f), sha: sha256(data), desc: desc ? desc[1].trim() : name };
    }
  }
  return out;
}

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const str = (v, max = 200) => {
  if (v == null) return null;
  const s = String(v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return s ? s.slice(0, max) : null;
};
const list = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);

function normalizeInventory(v, now = Date.now()) {
  if (!isObj(v)) return null;
  const up = isObj(v.updates) ? v.updates : {};
  const items = list(up.items, 100).filter(isObj).map(u => ({ title: str(u.title, 200), kb: str(u.kb, 20), severity: str(u.severity, 20) })).filter(u => u.title);
  const hw = isObj(v.hw) ? v.hw : {};
  const count = Number(up.count);
  return {
    at: now,
    user: str(v.user, 80),
    rebootRequired: typeof v.rebootRequired === 'boolean' ? v.rebootRequired : null,
    hw: { vendor: str(hw.vendor, 80), model: str(hw.model, 120), serial: str(hw.serial, 60) },
    apps: list(v.apps, 3000).filter(isObj).map(a => ({ name: str(a.name, 120), version: str(a.version, 40), publisher: str(a.publisher, 60) })).filter(a => a.name),
    updates: {
      checked: up.checked === true,
      count: Number.isFinite(count) && count >= 0 ? Math.min(count, 1e5) : items.length,
      items,
      error: str(up.error, 200),
    },
    hotfixes: list(v.hotfixes, 30).filter(isObj).map(h => ({ id: str(h.id, 20), date: str(h.date, 30) })).filter(h => h.id),
  };
}

function normalizeScripts(v) {
  return list(v, 40).filter(isObj)
    .filter(s => typeof s.name === 'string' && SCRIPT_NAME_RE.test(s.name) && typeof s.sha === 'string' && /^[a-f0-9]{64}$/i.test(s.sha))
    .map(s => ({ name: s.name, sha: s.sha.toLowerCase() }));
}

function validDeviceFields(body) {
  const out = {};
  if (typeof body.sshUser === 'string') {
    if (body.sshUser && !/^[A-Za-z0-9._-]{1,32}$/.test(body.sshUser)) return null;
    out.sshUser = body.sshUser;
  }
  if (typeof body.rustdeskId === 'string') {
    const id = body.rustdeskId.replace(/\s/g, '');
    if (id && !/^[A-Za-z0-9-]{6,32}$/.test(id)) return null;
    out.rustdeskId = id;
  }
  return out;
}

// DM_OFFLINE_QUIET: "18:00-08:30,weekends" (hub local time).
function quietHours(spec) {
  if (!spec) return () => false;
  const range = spec.match(/(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})/);
  const weekends = /weekends/.test(spec);
  const from = range ? +range[1] * 60 + +range[2] : null, to = range ? +range[3] * 60 + +range[4] : null;
  return (t = Date.now()) => {
    const d = new Date(t), m = d.getHours() * 60 + d.getMinutes();
    if (weekends && (d.getDay() === 0 || d.getDay() === 6)) return true;
    if (from == null) return false;
    return from <= to ? m >= from && m < to : m >= from || m < to;
  };
}

module.exports = { DeviceKeys, JoinKey, Audit, InventoryStore, vettedScripts, normalizeInventory, normalizeScripts, validDeviceFields, quietHours, sha256, SCRIPT_NAME_RE };
