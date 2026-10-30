#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tools = require('./windows-tools.json');
const dest = path.join(process.env.DM_DATA_DIR || path.join(process.env.HOME, '.local/share/device-monitor-hub'), 'downloads');
fs.mkdirSync(dest, { recursive: true });
(async () => {
  for (const t of Object.values(tools)) {
    const res = await fetch(t.url, { redirect: 'follow' });
    if (!res.ok) throw new Error(`${t.file}: HTTP ${res.status}`);
    const data = Buffer.from(await res.arrayBuffer());
    const sha = crypto.createHash('sha256').update(data).digest('hex');
    if (sha !== t.sha256) throw new Error(`${t.file}: hash mismatch ${sha}`);
    fs.writeFileSync(path.join(dest, t.file), data);
    console.log(`${t.file} ${t.version} ok (${data.length} bytes)`);
  }
})().catch(e => { console.error(e.message); process.exit(1); });
