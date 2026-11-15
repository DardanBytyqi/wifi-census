const REFRESH_MS = 2000;
const STALE_S = 300; // clients not seen for this long are greyed out

const $ = (id) => document.getElementById(id);
const modeSelect = $('scan-mode');
const channelSelect = $('scan-channel');
let knownChannels = '';

// helpers

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function ago(s) {
  if (s < 60) return `${Math.max(0, Math.round(s))}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

async function getJSON(url) {
  const res = await fetch(url);
  return res.json();
}

// scan controls

function setChannels(chans) {
  const key = chans.join(',');
  if (key === knownChannels) return;
  knownChannels = key;
  channelSelect.replaceChildren();
  for (const ch of chans) {
    const opt = el('option', `ch ${ch} (${ch <= 14 ? '2.4' : '5'}GHz)`);
    opt.value = ch;
    channelSelect.appendChild(opt);
  }
}

modeSelect.addEventListener('change', () => {
  channelSelect.disabled = modeSelect.value !== 'fixed';
});

$('scan-apply').addEventListener('click', async () => {
  const status = $('scan-status');
  const body = modeSelect.value === 'fixed'
    ? { mode: 'fixed', channel: Number(channelSelect.value) }
    : { mode: 'hop' };
  try {
    const res = await fetch('/api/mode', { method: 'POST', body: JSON.stringify(body) });
    status.textContent = res.ok ? 'applied' : 'error: ' + (await res.text()).trim();
  } catch {
    status.textContent = 'error';
  }
  setTimeout(() => { status.textContent = ''; }, 3000);
});

// node status

function renderNodes(nodes) {
  const box = $('nodes');
  if (!nodes || nodes.length === 0) {
    box.textContent = 'no node connected';
    return;
  }
  box.replaceChildren();
  const all = new Set();
  for (const n of nodes) {
    const chans = n.channels || [];
    chans.forEach((c) => all.add(c));
    const bands = chans.some((c) => c > 14) ? '2.4/5GHz' : '2.4GHz only';
    box.appendChild(el('div',
      `${n.name}: ${n.chip || '?'} · ${bands} · mode ${n.mode || '?'} · ` +
      `${n.rx_frames} frames rx, ${n.dropped} dropped, ${n.lines} lines`,
      n.online ? '' : 'off'));
  }
  setChannels([...all].sort((a, b) => a - b));
}

// access points

function apHeader(ap, nClients) {
  const name = ap.beaconed ? (ap.ssid || '(hidden)') : '(no beacon heard)';
  const h = el('h3', `${name} — ${ap.bssid} · ch${ap.channel} · `, ap.beaconed ? '' : 'ghost');
  h.appendChild(el('span', ap.band || '?', 'band'));
  if (ap.beaconed) h.append(` · ${ap.rssi}dBm`);
  if (ap.vendor) h.appendChild(el('span', ` · ${ap.vendor}`, 'vendor'));
  if (nClients > 0) h.appendChild(el('span', ` · ${nClients} ${nClients === 1 ? 'client' : 'clients'}`, 'count'));
  return h;
}

function clientRow(c) {
  const age = (Date.now() - new Date(c.last_seen)) / 1000;
  const kinds = c.kinds || [];
  const joinOnly = kinds.length > 0 && !kinds.includes('data');

  const tr = el('tr', undefined, age > STALE_S ? 'stale' : '');
  tr.appendChild(el('td', c.mac));
  tr.appendChild(el('td', c.vendor || (c.randomized ? '(random)' : '?'), c.vendor ? '' : 'muted'));
  tr.appendChild(el('td', c.rssi));
  tr.appendChild(el('td', ago(age)));
  tr.appendChild(el('td', c.frames));
  const k = el('td', kinds.join(' '), joinOnly ? 'joinonly' : '');
  if (joinOnly) k.title = 'auth/assoc but no data traffic seen';
  tr.appendChild(k);
  tr.appendChild(el('td', c.randomized, c.randomized ? 'rand' : ''));
  return tr;
}

function clientTable(clients) {
  const t = el('table');
  const hdr = el('tr');
  for (const s of ['client mac', 'vendor', 'rssi', 'last seen', 'frames', 'types', 'randomized']) {
    hdr.appendChild(el('th', s));
  }
  t.appendChild(hdr);
  clients.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
  for (const c of clients) t.appendChild(clientRow(c));
  return t;
}

function renderAPs(aps) {
  const out = $('aps');
  if (!aps || aps.length === 0) {
    out.textContent = 'no access points seen yet';
    return;
  }
  out.replaceChildren();
  let emptyShown = false;
  aps.forEach((ap, i) => {
    const clients = Object.values(ap.clients || {});
    if (clients.length === 0 && !emptyShown) {
      out.appendChild(el('h2', `APs with no clients seen (${aps.length - i})`, 'section'));
      emptyShown = true;
    }
    out.appendChild(apHeader(ap, clients.length));
    if (clients.length > 0) out.appendChild(clientTable(clients));
  });
}

// refresh loop

function refresh() {
  getJSON('/api/state').then(renderAPs).catch(() => {});
  getJSON('/api/nodes').then(renderNodes).catch(() => {});
}

refresh();
setInterval(refresh, REFRESH_MS);
