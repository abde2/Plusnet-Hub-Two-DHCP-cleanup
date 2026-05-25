#!/usr/bin/env node

const http = require('http');
const crypto = require('crypto');

const DEFAULT_ROUTER_IP = '192.168.1.254';
const PORT = 7823;

// ── Helpers ──────────────────────────────────────────────────────────────────

function routerRequest({ routerIp, path, method = 'GET', body = null, cookie = '', contentType = 'text/plain;charset=UTF-8' }) {
  return new Promise((resolve, reject) => {
    const headers = {
      'Host': routerIp,
      'User-Agent': 'Mozilla/5.0',
      'Accept': '*/*',
      'Connection': 'keep-alive',
      'Referer': `http://${routerIp}/my_network.htm`,
    };
    if (cookie) headers['Cookie'] = cookie;
    if (body) {
      headers['Content-Type'] = contentType;
      headers['Content-Length'] = Buffer.byteLength(body);
      headers['Origin'] = `http://${routerIp}`;
    }

    const opts = { hostname: routerIp, port: 80, path, method, headers };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function md5(str) {
  return crypto.createHash('md5').update(str, 'utf8').digest('hex');
}

function extractCookie(setCookieHeader) {
  if (!setCookieHeader) return '';
  const arr = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  const urn = arr.find(c => c.includes('urn='));
  return urn ? urn.split(';')[0] : '';
}

// ── Auth ──────────────────────────────────────────────────────────────────────

async function login(routerIp, password) {
  console.log(`Logging in to ${routerIp}...`);

  const homeResp = await routerRequest({ routerIp, path: '/' });
  let cookie = extractCookie(homeResp.headers['set-cookie']);
  if (!cookie) throw new Error('No session cookie — is the router IP correct?');

  const pwHash = md5(password);
  const loginBody = `GO=my_network.htm&usr=admin&pws=${pwHash}`;
  const loginResp = await new Promise((resolve, reject) => {
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(loginBody),
      'Host': routerIp,
      'Referer': `http://${routerIp}/`,
      'User-Agent': 'Mozilla/5.0',
      'Cookie': cookie,
    };
    const req = http.request({ hostname: routerIp, port: 80, path: '/login.cgi', method: 'POST', headers }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.write(loginBody);
    req.end();
  });

  if (loginResp.body.startsWith('login_error') || loginResp.body.startsWith('login_lock')) {
    throw new Error(`Login failed: ${loginResp.body.trim()}`);
  }

  const newCookie = extractCookie(loginResp.headers['set-cookie']);
  if (newCookie) cookie = newCookie;

  // The page meta pi is required for the first apply.cgi call (matches browser's getPi())
  const piMatch = loginResp.body.match(/<meta name="pi" content="([^"]+)"/);
  let pi = piMatch ? piMatch[1] : null;

  if (!pi) {
    console.log('  pi not in page meta, fetching from renewPi.js...');
    const piResp = await routerRequest({ routerIp, path: '/cgi/renewPi.js', cookie });
    const freshPi = piResp.body.trim();
    if (freshPi && !freshPi.includes('<')) {
      pi = freshPi;
    } else {
      throw new Error(`Could not get pi token (login page body length: ${loginResp.body.length}, starts: "${loginResp.body.substring(0, 50)}")`);
    }
  }

  console.log(`  Session: ${cookie}, pi: ${pi}`);
  return { cookie, pi };
}

// ── Fetch device list ─────────────────────────────────────────────────────────

async function fetchDevices(routerIp, cookie) {
  console.log('Fetching device list...');
  const t = Date.now();
  const resp = await routerRequest({ routerIp, path: `/cgi/cgi_myNetwork.js?t=${t}`, cookie });

  // Parse known_devices_update token
  const tokenMatch = resp.body.match(/addCfg\("known_devices_update",(\d+),'([^']*)'\)/);
  const updateToken = tokenMatch ? tokenMatch[1] : null;

  // Parse dhcpreserve entries: mac (URL-encoded) → { index, token }
  // e.g. addCfg("dhcpreserve5",18698710,'192%2E168%2E1%2E201%2CD6%3ADD%3AF9%3A91%3A83%3A6F%2C')
  const dhcpMap = {};
  const dhcpRe = /addCfg\("dhcpreserve(\d+)",(\d+),'([^']*)'\)/g;
  let m;
  while ((m = dhcpRe.exec(resp.body)) !== null) {
    const [, idx, token, val] = m;
    const parts = val.split('%2C'); // IP%2CMAC%2Cname
    if (parts.length >= 2) {
      const mac = parts[1]; // URL-encoded MAC e.g. D6%3ADD%3AF9%3A91%3A83%3A6F
      dhcpMap[mac] = { index: idx, token };
    }
  }

  // Parse known_device_list
  const listMatch = resp.body.match(/var known_device_list\s*=\s*(\[[\s\S]*?\]);/);
  if (!listMatch) {
    const fs = require('fs');
    fs.writeFileSync('cgi-response-debug.txt', resp.body.substring(0, 5000));
    throw new Error('Could not parse device list from router response (see cgi-response-debug.txt)');
  }

  let jsArray = listMatch[1]
    .replace(/,\s*null\s*\]/g, ']')
    .replace(/,\s*\]/g, ']')
    .replace(/'/g, '"')
    .replace(/([{,]\s*)([a-zA-Z_]\w*)\s*:/g, '$1"$2":')
    .trim();

  const devices = JSON.parse(jsArray);
  const decode = s => s ? decodeURIComponent(s.replace(/\+/g, ' ')) : '';
  const parsed = devices.map(d => ({
    mac: decode(d.mac),
    name: decode(d.name),
    hostname: decode(d.hostname),
    ip: decode(d.ip),
    activity: d.activity === '1',
    os: decode(d.os),
    device: decode(d.device),
    port: decode(d.port),
    time_first_seen: decode(d.time_first_seen),
    time_last_active: decode(d.time_last_active),
    raw_mac: d.mac,
    dhcp: dhcpMap[d.mac] || null, // DHCP reservation info if present
  }));

  console.log(`  Found ${parsed.length} devices (update token: ${updateToken}, ${Object.keys(dhcpMap).length} DHCP reservations)`);
  return { devices: parsed, updateToken };
}

// ── Fetch renewed pi token (used AFTER each apply.cgi call) ──────────────────

async function renewPi(routerIp, cookie) {
  const resp = await routerRequest({ routerIp, path: '/cgi/renewPi.js', cookie });
  const pi = resp.body.trim();
  if (!pi || pi.includes('<')) throw new Error('Failed to renew pi token');
  return pi;
}

// ── Remove devices in one batch apply.cgi call ───────────────────────────────
// Sends all MAC deletions as a single SET0 value (d,MAC1;d,MAC2;...)
// and one SETn per DHCP reservation to clear.
// Returns: { ok, newPi }

async function removeDevicesBatch(routerIp, cookie, updateToken, devicesToRemove, pi) {
  const delay = ms => new Promise(r => setTimeout(r, ms));

  // Combine all MAC deletions into one known_devices_update value
  const knownDevicesValue = devicesToRemove
    .map(d => `d%252C${encodeURIComponent(d.raw_mac)}%253B`)
    .join('');

  let body = `CMD=&GO=my_network.htm&SET0=${updateToken}%3D${knownDevicesValue}`;

  // One SET per DHCP reservation to clear
  let setIdx = 1;
  for (const d of devicesToRemove) {
    if (d.dhcp) {
      body += `&SET${setIdx}=${d.dhcp.token}%3D`;
      setIdx++;
    }
  }

  body += `&pi=${pi}`;

  console.log(`  apply.cgi: ${devicesToRemove.length} device(s), ${setIdx - 1} DHCP clears`);
  const resp = await routerRequest({ routerIp, path: '/apply.cgi', method: 'POST', body, cookie });
  const ok = resp.status === 200 && resp.body.startsWith('<!DOCTYPE');
  console.log(`  apply.cgi: status=${resp.status} ${ok ? 'OK' : 'FAILED — ' + resp.body.substring(0, 60)}`);

  await delay(700);
  const newPi = await renewPi(routerIp, cookie);
  return { ok, newPi };
}

// ── Web UI ────────────────────────────────────────────────────────────────────

const LOGIN_HTML = (error = '') => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Router Cleanup — Connect</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: #1e2333; border: 1px solid #2d3448; border-radius: 16px; padding: 36px; width: 100%; max-width: 400px; }
  h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 6px; color: #f8fafc; }
  .sub { color: #64748b; font-size: 0.875rem; margin-bottom: 28px; }
  label { display: block; font-size: 0.8rem; font-weight: 600; color: #94a3b8; margin-bottom: 6px; letter-spacing: 0.04em; text-transform: uppercase; }
  input { width: 100%; background: #0f1117; border: 1px solid #2d3448; border-radius: 8px; color: #e2e8f0; padding: 10px 14px; font-size: 0.95rem; outline: none; margin-bottom: 18px; }
  input:focus { border-color: #6366f1; }
  button { width: 100%; padding: 11px; border-radius: 8px; border: none; background: #6366f1; color: white; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
  button:hover { background: #4f46e5; }
  button:disabled { background: #374151; color: #6b7280; cursor: not-allowed; }
  .error { background: #450a0a; border: 1px solid #7f1d1d; border-radius: 8px; color: #fca5a5; font-size: 0.85rem; padding: 10px 14px; margin-bottom: 18px; }
  .spinner { display: none; text-align: center; margin-top: 14px; color: #64748b; font-size: 0.85rem; }
</style>
</head>
<body>
<div class="card">
  <h1>Router Cleanup</h1>
  <p class="sub">Plusnet Hub Two / BT Home Hub 6</p>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST" action="/connect" onsubmit="document.getElementById('btn').disabled=true;document.getElementById('spin').style.display='block';">
    <label>Router IP address</label>
    <input type="text" name="ip" value="${DEFAULT_ROUTER_IP}" required placeholder="192.168.1.254">
    <label>Admin password</label>
    <input type="password" name="password" required autofocus placeholder="Enter router password">
    <button type="submit" id="btn">Connect &amp; load devices</button>
  </form>
  <div class="spinner" id="spin">Connecting to router…</div>
</div>
</body>
</html>`;

const HTML = (devices, updateToken) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Router Cleanup</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; padding: 24px; }
  h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 4px; color: #f8fafc; }
  .subtitle { color: #94a3b8; font-size: 0.875rem; margin-bottom: 24px; }
  .controls { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
  .controls input { background: #1e2333; border: 1px solid #2d3448; border-radius: 8px; color: #e2e8f0; padding: 8px 12px; font-size: 0.875rem; flex: 1; min-width: 200px; outline: none; }
  .controls input:focus { border-color: #6366f1; }
  .btn { padding: 8px 16px; border-radius: 8px; border: none; font-size: 0.875rem; font-weight: 600; cursor: pointer; transition: all 0.15s; }
  .btn-ghost { background: #1e2333; color: #94a3b8; border: 1px solid #2d3448; }
  .btn-ghost:hover { color: #e2e8f0; border-color: #6366f1; }
  .btn-danger { background: #ef4444; color: white; }
  .btn-danger:hover { background: #dc2626; }
  .btn-danger:disabled { background: #374151; color: #6b7280; cursor: not-allowed; }
  .selected-count { color: #94a3b8; font-size: 0.875rem; white-space: nowrap; }
  .filters { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { padding: 5px 12px; border-radius: 20px; border: 1px solid #2d3448; background: #1e2333; color: #94a3b8; font-size: 0.8rem; cursor: pointer; transition: all 0.15s; }
  .filter-btn:hover, .filter-btn.active { background: #6366f1; border-color: #6366f1; color: white; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  thead th { text-align: left; padding: 10px 12px; color: #64748b; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #1e2333; position: sticky; top: 0; background: #0f1117; }
  tbody tr { border-bottom: 1px solid #1a1f2e; transition: background 0.1s; cursor: pointer; }
  tbody tr:hover { background: #1a1f2e; }
  tbody tr.selected { background: #1e2035; }
  td { padding: 10px 12px; vertical-align: middle; }
  td:first-child { width: 36px; }
  input[type=checkbox] { width: 16px; height: 16px; accent-color: #6366f1; cursor: pointer; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; font-weight: 600; }
  .badge-active { background: #052e16; color: #4ade80; border: 1px solid #16a34a; }
  .badge-inactive { background: #1c1917; color: #78716c; border: 1px solid #44403c; }
  .mac { font-family: monospace; color: #94a3b8; font-size: 0.8rem; }
  .ip { font-family: monospace; color: #7dd3fc; }
  .name { font-weight: 500; }
  .hostname { color: #94a3b8; font-size: 0.8rem; }
  .port-badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 0.72rem; background: #1e2333; border: 1px solid #2d3448; color: #64748b; }
  .last-seen { color: #64748b; font-size: 0.8rem; white-space: nowrap; }
  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100; align-items: center; justify-content: center; }
  .modal-overlay.show { display: flex; }
  .modal { background: #1e2333; border: 1px solid #2d3448; border-radius: 16px; padding: 28px; max-width: 480px; width: 100%; }
  .modal h2 { font-size: 1.1rem; margin-bottom: 8px; color: #f8fafc; }
  .modal p { color: #94a3b8; font-size: 0.875rem; margin-bottom: 20px; line-height: 1.5; }
  .modal-list { background: #0f1117; border-radius: 8px; padding: 12px; margin-bottom: 20px; max-height: 200px; overflow-y: auto; }
  .modal-list div { font-size: 0.8rem; padding: 3px 0; color: #e2e8f0; }
  .modal-actions { display: flex; gap: 10px; justify-content: flex-end; }
  .progress { display: none; margin-top: 16px; }
  .progress-bar { height: 6px; background: #1e2333; border-radius: 3px; overflow: hidden; }
  .progress-fill { height: 100%; background: #6366f1; transition: width 0.3s; border-radius: 3px; }
  .progress-text { font-size: 0.8rem; color: #94a3b8; margin-top: 6px; }
  .toast { position: fixed; bottom: 24px; right: 24px; background: #1e2333; border: 1px solid #2d3448; border-radius: 10px; padding: 12px 18px; font-size: 0.875rem; z-index: 200; opacity: 0; transition: opacity 0.3s; pointer-events: none; }
  .toast.show { opacity: 1; }
  .toast.success { border-color: #16a34a; color: #4ade80; }
  .toast.error { border-color: #dc2626; color: #f87171; }
  .empty { text-align: center; padding: 48px; color: #4b5563; }
</style>
</head>
<body>

<h1>Router Device Cleanup</h1>
<p class="subtitle">Plusnet Hub Two · ${devices.length} devices total · Select devices to remove from history</p>

<div class="controls">
  <input type="text" id="search" placeholder="Search by name, IP, or MAC..." oninput="applyFilters()">
  <button class="btn btn-ghost" onclick="selectAll()">Select all visible</button>
  <button class="btn btn-ghost" onclick="deselectAll()">Deselect all</button>
  <span class="selected-count" id="selCount">0 selected</span>
  <button class="btn btn-ghost" onclick="location.reload()">Refresh list</button>
  <button class="btn btn-ghost" onclick="window.location='/csv'">Download CSV</button>
  <button class="btn btn-danger" id="removeBtn" disabled onclick="showConfirm()">Remove selected</button>
</div>

<div class="filters">
  <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
  <button class="filter-btn" onclick="setFilter('inactive', this)">Inactive only</button>
  <button class="filter-btn" onclick="setFilter('unknown', this)">Unknown devices</button>
  <button class="filter-btn" onclick="setFilter('active', this)">Currently active</button>
</div>

<table>
  <thead>
    <tr>
      <th><input type="checkbox" id="masterCb" onchange="toggleAll(this)"></th>
      <th>Name / Hostname</th>
      <th>IP Address</th>
      <th>MAC Address</th>
      <th>Port</th>
      <th>Last Active</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody id="deviceTable"></tbody>
</table>

<div class="empty" id="emptyMsg" style="display:none">No devices match your filter</div>

<div class="modal-overlay" id="modalOverlay">
  <div class="modal">
    <h2>Confirm Removal</h2>
    <p>The following <span id="confirmCount">0</span> devices will be permanently removed from the router's device history.</p>
    <div class="modal-list" id="confirmList"></div>
    <div class="progress" id="progressWrap">
      <div class="progress-bar"><div class="progress-fill" id="progressFill" style="width:0%"></div></div>
      <div class="progress-text" id="progressText">Removing...</div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal()" id="cancelBtn">Cancel</button>
      <button class="btn btn-danger" onclick="doRemove()" id="confirmBtn">Remove all</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const DEVICES = ${JSON.stringify(devices)};
const UPDATE_TOKEN = ${JSON.stringify(updateToken)};
let currentFilter = 'all';
let selected = new Set();

function relativeTime(dateStr) {
  if (!dateStr || dateStr.startsWith('1981')) return 'Unknown';
  const d = new Date(dateStr.replace(/\\//g, '-').replace(' ', 'T'));
  if (isNaN(d)) return dateStr;
  const diff = Date.now() - d;
  const days = Math.floor(diff / 86400000);
  if (days === 0) return 'Today';
  if (days === 1) return 'Yesterday';
  if (days < 30) return days + 'd ago';
  if (days < 365) return Math.floor(days/30) + 'mo ago';
  return Math.floor(days/365) + 'y ago';
}

function getVisible() {
  const q = document.getElementById('search').value.toLowerCase();
  return DEVICES.filter(d => {
    const matchSearch = !q || d.name.toLowerCase().includes(q) || d.ip.includes(q) || d.mac.toLowerCase().includes(q) || d.hostname.toLowerCase().includes(q);
    const matchFilter = currentFilter === 'all' ? true
      : currentFilter === 'inactive' ? !d.activity
      : currentFilter === 'unknown' ? (d.name.startsWith('unknown_') || d.name === d.mac)
      : currentFilter === 'active' ? d.activity
      : true;
    return matchSearch && matchFilter;
  });
}

function render() {
  const visible = getVisible();
  const tbody = document.getElementById('deviceTable');
  const empty = document.getElementById('emptyMsg');
  if (visible.length === 0) {
    tbody.innerHTML = '';
    empty.style.display = '';
  } else {
    empty.style.display = 'none';
    tbody.innerHTML = visible.map(d => {
      const sel = selected.has(d.mac);
      const name = d.name || d.hostname || d.mac;
      return \`<tr class="\${sel ? 'selected' : ''}" onclick="toggleRow('\${d.mac}', event)">
        <td><input type="checkbox" \${sel ? 'checked' : ''} onclick="toggleRow('\${d.mac}', event)" data-mac="\${d.mac}"></td>
        <td>
          <div class="name">\${name}</div>
          \${d.hostname && d.hostname !== name ? \`<div class="hostname">\${d.hostname}</div>\` : ''}
        </td>
        <td><span class="ip">\${d.ip || '-'}</span></td>
        <td><span class="mac">\${d.mac}</span></td>
        <td><span class="port-badge">\${d.port || '-'}</span></td>
        <td><span class="last-seen">\${relativeTime(d.time_last_active)}</span></td>
        <td><span class="badge \${d.activity ? 'badge-active' : 'badge-inactive'}">\${d.activity ? 'Active' : 'Inactive'}</span></td>
      </tr>\`;
    }).join('');
  }
  updateCount();
}

function toggleRow(mac, e) {
  if (e.target.tagName === 'INPUT') return;
  if (selected.has(mac)) selected.delete(mac); else selected.add(mac);
  render();
}

function toggleAll(cb) {
  if (cb.checked) getVisible().forEach(d => selected.add(d.mac));
  else getVisible().forEach(d => selected.delete(d.mac));
  render();
}

function selectAll() { getVisible().forEach(d => selected.add(d.mac)); render(); }
function deselectAll() { selected.clear(); render(); }

function updateCount() {
  const n = selected.size;
  document.getElementById('selCount').textContent = n + ' selected';
  document.getElementById('removeBtn').disabled = n === 0;
}

function applyFilters() { render(); }

function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  render();
}

function showConfirm() {
  const sel = DEVICES.filter(d => selected.has(d.mac));
  document.getElementById('confirmCount').textContent = sel.length;
  document.getElementById('confirmList').innerHTML = sel.map(d =>
    \`<div>· \${d.name || d.mac} (\${d.mac}) — \${d.ip || 'no IP'}</div>\`
  ).join('');
  document.getElementById('progressWrap').style.display = 'none';
  document.getElementById('confirmBtn').disabled = false;
  document.getElementById('cancelBtn').disabled = false;
  document.getElementById('modalOverlay').classList.add('show');
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('show');
}

function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.classList.remove('show'), 3500);
}

async function doRemove() {
  const sel = DEVICES.filter(d => selected.has(d.mac));
  document.getElementById('confirmBtn').disabled = true;
  document.getElementById('cancelBtn').disabled = true;
  document.getElementById('progressWrap').style.display = 'block';
  document.getElementById('progressFill').style.width = '2%';
  document.getElementById('progressText').textContent = \`Starting removal of \${sel.length} devices...\`;

  // Poll /progress while the server works
  const pollInterval = setInterval(async () => {
    try {
      const p = await (await fetch('/progress')).json();
      if (p && p.total) {
        const pct = Math.round((p.done / p.total) * 95) + 2;
        document.getElementById('progressFill').style.width = pct + '%';
        document.getElementById('progressText').textContent =
          \`Removing \${p.current} (\${p.done}/\${p.total})...\`;
      }
    } catch (_) {}
  }, 800);

  try {
    const resp = await fetch('/remove-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ macs: sel.map(d => d.mac) }),
    });
    const result = await resp.json();
    clearInterval(pollInterval);

    document.getElementById('progressFill').style.width = '100%';

    if (result.alreadyGone) {
      document.getElementById('progressText').textContent = 'Already removed — page is stale';
      setTimeout(() => { closeModal(); showToast('These devices were already removed — refresh the page', 'error'); }, 600);
      return;
    }

    const msg = result.removed.length + ' removed' + (result.failed && result.failed.length ? ', ' + result.failed.length + ' failed' : '');
    document.getElementById('progressText').textContent = msg;

    setTimeout(() => {
      closeModal();
      if (result.removed.length > 0) {
        showToast('Removed ' + result.removed.length + ' devices', result.failed && result.failed.length ? 'error' : 'success');
        const removedSet = new Set(result.removed);
        sel.forEach(d => selected.delete(d.mac));
        DEVICES.splice(0, DEVICES.length, ...DEVICES.filter(d => !removedSet.has(d.mac)));
        render();
      } else {
        showToast('Failed — router rejected all requests', 'error');
      }
    }, 800);
  } catch (e) {
    clearInterval(pollInterval);
    document.getElementById('progressText').textContent = 'Error: ' + e.message;
  }
}

render();
</script>
</body>
</html>`;

// ── Server ────────────────────────────────────────────────────────────────────

async function main() {
  // Session state — null until the user logs in via the web UI
  let session = null; // { routerIp, cookie, devices, updateToken, currentPi, deviceByMac }
  let batchProgress = null;

  const server = http.createServer(async (req, res) => {
    // ── Login page ───────────────────────────────────────────────────────────
    if (req.method === 'GET' && req.url === '/') {
      if (session) {
        res.writeHead(302, { Location: '/devices' }); res.end(); return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(LOGIN_HTML());
      return;
    }

    if (req.method === 'POST' && req.url === '/connect') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', async () => {
        const params = new URLSearchParams(body);
        const routerIp = (params.get('ip') || '').trim();
        const password = (params.get('password') || '').trim();
        try {
          const auth = await login(routerIp, password);
          const { devices, updateToken } = await fetchDevices(routerIp, auth.cookie);
          const deviceByMac = {};
          devices.forEach(d => { deviceByMac[d.mac] = d; });
          session = { routerIp, cookie: auth.cookie, devices, updateToken, currentPi: auth.pi, deviceByMac };
          res.writeHead(302, { Location: '/devices' }); res.end();
        } catch (e) {
          console.error('Login failed:', e.message);
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(LOGIN_HTML(e.message.includes('login_error') ? 'Wrong password — please try again.' : `Could not connect: ${e.message}`));
        }
      });
      return;
    }

    // ── Require session for everything below ─────────────────────────────────
    if (!session) {
      res.writeHead(302, { Location: '/' }); res.end(); return;
    }

    const { routerIp, deviceByMac } = session;

    if (req.method === 'GET' && req.url === '/devices') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(HTML(session.devices, session.updateToken));
      return;
    }

    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(302, { Location: '/devices' }); res.end(); return;
    }

    if (req.method === 'GET' && req.url === '/progress') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(batchProgress));
      return;
    }

    if (req.method === 'GET' && req.url === '/csv') {
      const csvRow = d => [
        d.name, d.hostname, d.ip, d.mac, d.port,
        d.activity ? 'Active' : 'Inactive',
        d.time_last_active || '', d.time_first_seen || '', d.os || '', d.device || '',
        d.dhcp ? 'Yes' : 'No',
      ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',');
      const header = 'Name,Hostname,IP,MAC,Port,Status,Last Active,First Seen,OS,Device Type,DHCP Reserved';
      const csv = [header, ...session.devices.map(csvRow)].join('\r\n');
      const now = new Date();
      const stamp = `${now.getDate()}_${now.getMonth()+1}_${now.getFullYear()}`;
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="router_devices_${stamp}.csv"`,
      });
      res.end(csv);
      return;
    }

    if (req.method === 'POST' && req.url === '/remove-batch') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', async () => {
        try {
          const { macs } = JSON.parse(body);
          const devicesToRemove = macs.map(mac => deviceByMac[mac]).filter(Boolean);
          console.log(`  /remove-batch: ${macs.length} requested, ${devicesToRemove.length} matched`);
          if (devicesToRemove.length === 0) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true, removed: [], failed: [], alreadyGone: true }));
            return;
          }

          const removed = [], failed = [];
          batchProgress = { total: devicesToRemove.length, done: 0, current: '', removed, failed };

          try { session.currentPi = await renewPi(routerIp, session.cookie); } catch (_) {}

          for (const device of devicesToRemove) {
            batchProgress.current = device.name || device.mac;
            try {
              const fresh = await fetchDevices(routerIp, session.cookie);
              session.updateToken = fresh.updateToken;
              const freshDevice = fresh.devices.find(d => d.mac === device.mac);
              if (freshDevice) { device.raw_mac = freshDevice.raw_mac; device.dhcp = freshDevice.dhcp; }

              const result = await removeDevicesBatch(routerIp, session.cookie, session.updateToken, [device], session.currentPi);
              session.currentPi = result.newPi;
              if (result.ok) {
                delete deviceByMac[device.mac];
                removed.push(device.mac);
              } else {
                failed.push(device.mac);
              }
            } catch (e) {
              console.error(`  Failed to remove ${device.mac}:`, e.message);
              failed.push(device.mac);
            }
            batchProgress.done++;
          }

          batchProgress = null;
          console.log(`  Done: ${removed.length} removed, ${failed.length} failed`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: failed.length === 0, removed, failed }));
        } catch (e) {
          console.error('Batch remove error:', e.message);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: e.message }));
        }
      });
      return;
    }

    res.writeHead(404);
    res.end('Not found');
  });

  server.listen(PORT, '127.0.0.1', () => {
    console.log(`\nRouter Cleanup running — open in your browser:`);
    console.log(`   http://localhost:${PORT}\n`);
  });
}

main();
