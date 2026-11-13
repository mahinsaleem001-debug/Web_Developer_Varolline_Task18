const app = document.getElementById('app');
const state = { meta: { vuln: [] }, user: null, csrf: null, view: 'notes', authTab: 'login', notes: [], q: '', sort: 'new', users: [], uq: '', flash: null, remaining: null, remainingAt: 0, checks: null, dial: 0 };
const weak = (flag) => state.meta.vuln.includes(flag);

/* localStorage can throw (private windows, blocked storage), so every use goes through here */
const keep = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } }
};

/* ------------------------------------------------------------------ helpers */
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2).toLowerCase(), v);
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) n.append(k.nodeType ? k : document.createTextNode(String(k))); // text is always inserted as text
  return n;
}
const NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs = {}, ...kids) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  n.append(...kids);
  return n;
}
const ICONS = {
  lock: 'M6 10V8a6 6 0 1 1 12 0v2M5 10h14v11H5zM12 14v3',
  notes: 'M7 3h8l4 4v14H7zM15 3v4h4M10 12h6M10 16h6',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z M9 12l2 2 4-4',
  users: 'M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0M4 21a8 8 0 0 1 16 0',
  sun: 'M12 4V2M12 22v-2M4 12H2M22 12h-2M5.6 5.6L4.2 4.2M19.8 19.8l-1.4-1.4M5.6 18.4l-1.4 1.4M19.8 4.2l-1.4 1.4M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10z',
  moon: 'M20 14.5A8.5 8.5 0 1 1 9.5 4a7 7 0 0 0 10.5 10.5z',
  plus: 'M12 5v14M5 12h14',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-5-5',
  edit: 'M4 20h4L19 9l-4-4L4 16z',
  trash: 'M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  eyeoff: 'M3 3l18 18M10.6 6.1A9.8 9.8 0 0 1 12 6c6 0 10 6 10 6a16 16 0 0 1-3.3 3.8M6.6 6.7C3.8 8.5 2 12 2 12s4 7 10 7c1.5 0 2.8-.4 4-1M9.9 9.9a3 3 0 0 0 4.2 4.2',
  check: 'M5 12l5 5L20 7',
  x: 'M6 6l12 12M18 6L6 18',
  out: 'M10 4H5v16h5M15 8l4 4-4 4M9 12h10'
};
const icon = (name, cls = 'i') => svgEl('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', class: cls }, svgEl('path', { d: ICONS[name] }));

const hue = (s) => [...s].reduce((a, c) => a + c.charCodeAt(0), 0) % 6;
const avatar = (name, sm) => el('span', { class: `avatar av-${hue(name)}${sm ? ' sm' : ''}`, 'aria-hidden': 'true' }, name.slice(0, 2).toUpperCase());
function ago(iso) {
  const s = Math.max(1, Math.round((Date.now() - new Date(iso)) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}
const words = (t) => (t.trim() ? t.trim().split(/\s+/).length : 0);

/* ------------------------------------------------------------------ theme */
function applyTheme(t) { document.documentElement.dataset.theme = t; keep.set('theme', t); }
const currentTheme = () => document.documentElement.dataset.theme || 'light';
(function initTheme() {
  const saved = keep.get('theme');
  document.documentElement.dataset.theme = saved || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
})();
const themeBtn = () => el('button', { class: 'icon-btn', type: 'button', 'aria-label': currentTheme() === 'dark' ? 'Switch to light theme' : 'Switch to dark theme', onClick: () => { applyTheme(currentTheme() === 'dark' ? 'light' : 'dark'); render(); } }, icon(currentTheme() === 'dark' ? 'sun' : 'moon'));

/* ------------------------------------------------------------------ toasts and dialogs */
const toasts = document.body.appendChild(el('div', { id: 'toasts', 'aria-live': 'polite' }));
function toast(text, action) {
  const t = el('div', { class: 'toast' }, el('span', {}, text));
  if (action) t.append(el('button', { type: 'button', onClick: () => { t.remove(); action.run(); } }, action.label));
  while (toasts.children.length >= 2) toasts.firstChild.remove(); // never pile up
  toasts.append(t);
  setTimeout(() => t.remove(), action ? 7000 : 4000);
}
function openDialog(build) {
  return new Promise((resolve) => {
    const d = el('dialog');
    const close = (v) => { d.close(); d.remove(); resolve(v); };
    d.append(build(close));
    d.addEventListener('cancel', (e) => { e.preventDefault(); close(null); });
    document.body.append(d); d.showModal();
  });
}
const confirmDialog = (title, text, label) => openDialog((close) => el('div', { class: 'dlg' }, el('h3', {}, title), el('p', {}, text),
  el('div', { class: 'actions' }, el('button', { class: 'btn ghost', type: 'button', onClick: () => close(false) }, 'Cancel'), el('button', { class: 'btn danger', type: 'button', onClick: () => close(true) }, label))));

/* ------------------------------------------------------------------ api */
async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (state.csrf) headers['X-CSRF-Token'] = state.csrf;
  const legacy = weak('cookieflags') && keep.get('token'); // only the weak build keeps a token in JavaScript-readable storage
  if (legacy) headers.Authorization = `Bearer ${legacy}`;
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const rem = res.headers.get('X-Session-Remaining');
  if (rem !== null) { state.remaining = Number(rem); state.remainingAt = Date.now(); }
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && state.user && !path.startsWith('/api/login')) expire();
  return { ok: res.ok, status: res.status, data, headers: res.headers };
}
function flash(kind, text, list) { state.flash = { kind, text, list }; }
const flashEl = () => { const f = state.flash; state.flash = null; return f ? el('div', { class: `msg ${f.kind}`, role: f.kind === 'error' ? 'alert' : 'status' }, f.text, f.list && el('ul', {}, f.list.map((x) => el('li', {}, x)))) : null; };

/* ------------------------------------------------------------------ session timer */
const R = 18, C = 2 * Math.PI * R;
function sessionTimer() {
  const ring = svgEl('svg', { viewBox: '0 0 44 44', 'aria-hidden': 'true' },
    svgEl('circle', { class: 'ring-bg', cx: 22, cy: 22, r: R, fill: 'none', 'stroke-width': 4 }),
    svgEl('circle', { class: 'ring-fg', id: 'ring-fg', cx: 22, cy: 22, r: R, fill: 'none', 'stroke-width': 4, 'stroke-dasharray': C, 'stroke-dashoffset': 0, transform: 'rotate(-90 22 22)' }));
  return el('div', { class: 'timer', id: 'timer', role: 'timer', 'aria-label': 'Time until your session ends' }, ring,
    el('div', {}, el('small', {}, 'Session ends in'), el('strong', { id: 'timer-text' }, '--:--')));
}
function remainingMs() { return state.remaining == null ? null : state.remaining - (Date.now() - state.remainingAt); }
function tick() {
  if (!state.user) return;
  const ms = remainingMs();
  if (ms == null) return;
  if (ms <= 0) return expire();
  const s = Math.ceil(ms / 1000), mm = String(Math.floor(s / 60)).padStart(2, '0'), ss = String(s % 60).padStart(2, '0');
  const t = document.getElementById('timer-text'), r = document.getElementById('ring-fg'), box = document.getElementById('timer');
  if (t) t.textContent = `${mm}:${ss}`;
  if (r) r.setAttribute('stroke-dashoffset', String(C * (1 - Math.min(1, ms / (30 * 60 * 1000)))));
  if (box) box.classList.toggle('warn', ms < 5 * 60 * 1000);
}
setInterval(tick, 1000);
function expire() {
  if (!state.user) return;
  keep.del('token');
  state.user = null; state.csrf = null; state.notes = []; state.authTab = 'login';
  flash('error', 'Your session ended. Sign in again to continue.');
  render();
}

/* ------------------------------------------------------------------ password strength (a hint only, the server decides) */
function strength(pw, username) {
  if (!pw) return { n: 0, label: '' };
  const low = pw.toLowerCase();
  if (/password|qwerty|letmein|123456|abcdef/.test(low) || (username.length >= 3 && low.includes(username.toLowerCase()))) return { n: 1, label: 'Easy to guess' };
  let n = 0;
  if (pw.length >= 8) n++;
  if (pw.length >= 12) n++;
  if (pw.length >= 16 || (/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw) && /[^\w]/.test(pw))) n++;
  if (pw.length >= 20) n++;
  n = Math.max(1, Math.min(4, n));
  return { n, label: ['', 'Weak', 'Fair', 'Good', 'Strong'][n] };
}
function strengthBlock(getPw, getUser) {
  const meter = el('div', { class: 'meter', 'aria-hidden': 'true' }, el('span'), el('span'), el('span'), el('span'));
  const label = el('div', { class: 'meter-label', 'aria-live': 'polite' });
  const rules = el('ul', { class: 'rules', 'aria-label': 'Password rules' },
    el('li', { 'data-r': 'len' }, 'At least 12 characters'),
    el('li', { 'data-r': 'user' }, 'Does not contain your username'),
    el('li', {}, 'Not a common password (the server checks this)'));
  const update = () => {
    const pw = getPw(), u = getUser();
    const s = strength(pw, u);
    meter.className = `meter s${s.n}`; label.textContent = s.label ? `Strength: ${s.label}` : '';
    rules.querySelector('[data-r=len]').classList.toggle('ok', pw.length >= 12);
    rules.querySelector('[data-r=user]').classList.toggle('ok', pw.length > 0 && !(u.length >= 3 && pw.toLowerCase().includes(u.toLowerCase())));
  };
  return { nodes: [meter, label, rules], update };
}
function passwordField(id, label, autocomplete, onInput) {
  const input = el('input', { id, name: id, type: 'password', autocomplete, required: true });
  const caps = el('div', { class: 'caps', role: 'status' });
  const toggle = el('button', { class: 'icon-btn', type: 'button', 'aria-label': `Show ${label.toLowerCase()}`, 'aria-pressed': 'false' }, icon('eye'));
  toggle.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.setAttribute('aria-pressed', String(show)); toggle.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} ${label.toLowerCase()}`);
    toggle.replaceChildren(icon(show ? 'eyeoff' : 'eye'));
  });
  input.addEventListener('keyup', (e) => { caps.textContent = e.getModifierState?.('CapsLock') ? 'Caps Lock is on' : ''; });
  input.addEventListener('input', () => onInput?.(input));
  const wrap = el('div', { class: 'field' }, el('label', { for: id }, label), el('div', { class: 'pw' }, input, toggle), caps);
  return { wrap, input };
}

/* ------------------------------------------------------------------ auth view */
function vaultSvg() {
  const ticks = [];
  for (let i = 0; i < 48; i++) {
    const a = (i / 48) * Math.PI * 2, major = i % 4 === 0, r1 = major ? 86 : 90, r2 = 98;
    ticks.push(svgEl('line', { class: `tick${major ? ' major' : ''}`, x1: 100 + Math.cos(a) * r1, y1: 100 + Math.sin(a) * r1, x2: 100 + Math.cos(a) * r2, y2: 100 + Math.sin(a) * r2 }));
  }
  const ring = svgEl('g', { class: 'ring', id: 'dial' }, ...ticks);
  ring.style.transform = `rotate(${state.dial}deg)`; // set through the DOM, so the strict CSP stays intact
  return svgEl('svg', { class: 'vault', id: 'vault', viewBox: '0 0 200 200', role: 'img', 'aria-label': 'A combination lock that turns as you type' },
    svgEl('circle', { class: 'glow', cx: 100, cy: 100, r: 100, fill: 'none', stroke: '#5fd3b4', 'stroke-width': 3 }),
    ring,
    svgEl('circle', { cx: 100, cy: 100, r: 70, fill: '#0b1f1b', stroke: '#2b5a4f', 'stroke-width': 2 }),
    svgEl('path', { class: 'shackle', d: 'M80 92V76a20 20 0 0 1 40 0v16', fill: 'none', stroke: '#9fe6d2', 'stroke-width': 8, 'stroke-linecap': 'round' }),
    svgEl('rect', { x: 68, y: 92, width: 64, height: 46, rx: 9, fill: '#5fd3b4' }),
    svgEl('circle', { cx: 100, cy: 111, r: 6, fill: '#0b1f1b' }),
    svgEl('rect', { x: 97.5, y: 113, width: 5, height: 12, rx: 2, fill: '#0b1f1b' }));
}
function turnDial(step = 11) { state.dial += step; const d = document.getElementById('dial'); if (d) d.style.transform = `rotate(${state.dial}deg)`; }

function viewAuth() {
  const isLogin = state.authTab === 'login';
  const u = el('input', { id: 'username', name: 'username', autocomplete: 'username', required: true, autocapitalize: 'none', spellcheck: 'false' });
  let sb = null;
  const pf = passwordField('password', 'Password', isLogin ? 'current-password' : 'new-password', () => { sb?.update(); turnDial(); });
  if (!isLogin) sb = strengthBlock(() => pf.input.value, () => u.value);
  u.addEventListener('input', () => { sb?.update(); turnDial(-7); });
  const submit = el('button', { class: 'btn block', type: 'submit' }, isLogin ? 'Sign in' : 'Create account');
  const form = el('form', {
    novalidate: true,
    onSubmit: async (e) => {
      e.preventDefault(); submit.disabled = true;
      const r = await api('POST', isLogin ? '/api/login' : '/api/register', { username: u.value, password: pf.input.value });
      submit.disabled = false;
      if (!r.ok) { flash('error', r.data.error || 'Something went wrong', r.data.problems); return render(); }
      if (isLogin) return afterLogin(r.data);
      const l = await api('POST', '/api/login', { username: u.value, password: pf.input.value });
      if (l.ok) return afterLogin(l.data);
      state.authTab = 'login'; flash('ok', 'Account created. Sign in to continue.'); render();
    }
  },
  el('div', { class: 'field' }, el('label', { for: 'username' }, 'Username'), u, !isLogin && el('span', { class: 'hint' }, '3 to 32 characters: letters, numbers, underscore')),
  pf.wrap, sb && sb.nodes, submit);

  const tab = (id, label) => el('button', { type: 'button', role: 'tab', 'aria-selected': String(state.authTab === id), onClick: () => { state.authTab = id; state.flash = null; render(); } }, label);
  const feature = (title, text) => el('li', {}, icon('check'), el('span', {}, el('strong', {}, title), text));
  return el('div', { class: 'auth' + (state.meta.vuln.length ? ' with-banner' : '') },
    el('aside', { class: 'auth-side', 'aria-label': 'About Lockbox' },
      el('h1', { class: 'brand' }, icon('lock', 'i'), 'Lockbox'),
      vaultSvg(),
      el('h2', {}, 'Private notes, behind a hardened login.'),
      el('ul', {},
        feature('A session cookie you cannot read', 'HttpOnly and SameSite, so scripts and other sites cannot take it.'),
        feature('Every change is verified', 'A CSRF token and an origin check guard each request.'),
        feature('Passwords stay secret', 'Hashed with scrypt. Guessing is rate limited.'),
        feature('Your notes are yours', 'Ownership is checked on the server, every time.'))),
    el('main', { class: 'auth-main' }, el('div', { class: 'theme' }, themeBtn()),
      el('div', { class: 'card' },
        el('div', { class: 'tabs', role: 'tablist' }, tab('login', 'Sign in'), tab('register', 'Create account')),
        el('h2', {}, isLogin ? 'Welcome back' : 'Create your account'),
        el('p', { class: 'sub' }, isLogin ? 'Sign in to see your notes.' : 'It takes a few seconds.'),
        flashEl(), form)));
}

async function afterLogin(data) {
  state.user = data.user; state.csrf = data.csrfToken; state.view = 'notes'; state.checks = null;
  if (data.token) keep.set('token', data.token); // weak build only: the server returns a token in the body
  const v = document.getElementById('vault');
  if (v && !matchMedia('(prefers-reduced-motion: reduce)').matches) { v.classList.add('open'); await new Promise((r) => setTimeout(r, 650)); }
  await loadNotes(); render();
}
async function signOut() {
  await api('POST', '/api/logout');
  keep.del('token');
  state.user = null; state.csrf = null; state.notes = []; state.authTab = 'login'; state.remaining = null; render();
}

/* ------------------------------------------------------------------ notes */
async function loadNotes() { const r = await api('GET', '/api/notes'); state.notes = r.ok ? r.data.notes : []; }

function noteDialog(note) {
  return openDialog((close) => {
    const t = el('input', { id: 'nt', required: true, maxlength: '100', value: note?.title ?? '' });
    const b = el('textarea', { id: 'nb', maxlength: '5000' }); b.value = note?.body ?? '';
    const err = el('div', { role: 'alert' });
    const form = el('form', {
      novalidate: true,
      onSubmit: async (e) => {
        e.preventDefault();
        if (!t.value.trim()) { err.replaceChildren(el('div', { class: 'msg error' }, 'Give the note a title')); return t.focus(); }
        const r = note ? await api('PUT', `/api/notes/${note.id}`, { title: t.value, body: b.value }) : await api('POST', '/api/notes', { title: t.value, body: b.value });
        if (!r.ok) return err.replaceChildren(el('div', { class: 'msg error' }, r.data.error || 'Could not save'));
        close(r.data.note);
      }
    }, err,
    el('div', { class: 'field' }, el('label', { for: 'nt' }, 'Title'), t),
    el('div', { class: 'field' }, el('label', { for: 'nb' }, 'Note'), b),
    el('div', { class: 'actions' }, el('button', { class: 'btn ghost', type: 'button', onClick: () => close(null) }, 'Cancel'), el('button', { class: 'btn', type: 'submit' }, note ? 'Save changes' : 'Save note')));
    queueMicrotask(() => t.focus());
    return el('div', { class: 'dlg' }, el('h3', {}, note ? 'Edit note' : 'New note'), form);
  });
}
async function addNote() { const n = await noteDialog(null); if (n) { await loadNotes(); render(); toast('Note saved'); } }
async function editNote(note) { const n = await noteDialog(note); if (n) { await loadNotes(); render(); toast('Note updated'); } }
async function deleteNote(note) {
  if (!(await confirmDialog('Delete this note?', `"${note.title}" will be removed.`, 'Delete'))) return;
  await api('DELETE', `/api/notes/${note.id}`); await loadNotes(); render();
  toast('Note deleted', { label: 'Undo', run: async () => { await api('POST', '/api/notes', { title: note.title, body: note.body }); await loadNotes(); render(); } });
}

function noteCard(n) {
  const body = el('div', { class: 'body' });
  if (weak('xss')) body.innerHTML = n.body; else body.textContent = n.body; // the weak build renders note text as HTML
  return el('article', { class: 'note' }, el('h3', {}, n.title), body,
    el('div', { class: 'meta' }, `Edited ${ago(n.updatedAt)}`, el('span', { class: 'sp' }),
      el('button', { class: 'icon-btn', type: 'button', 'aria-label': `Edit note ${n.title}`, onClick: () => editNote(n) }, icon('edit')),
      el('button', { class: 'icon-btn', type: 'button', 'aria-label': `Delete note ${n.title}`, onClick: () => deleteNote(n) }, icon('trash'))));
}
function visibleNotes() {
  const q = state.q.trim().toLowerCase();
  const list = state.notes.filter((n) => !q || n.title.toLowerCase().includes(q) || n.body.toLowerCase().includes(q));
  const by = { new: (a, b) => new Date(b.updatedAt) - new Date(a.updatedAt), old: (a, b) => new Date(a.updatedAt) - new Date(b.updatedAt), az: (a, b) => a.title.localeCompare(b.title) };
  return list.sort(by[state.sort]);
}
function fillNoteList() {
  const box = document.getElementById('note-list'); if (!box) return;
  const list = visibleNotes();
  box.replaceChildren(...(list.length ? list.map(noteCard)
    : [state.notes.length
      ? el('div', { class: 'empty' }, el('h3', {}, 'No notes match'), el('p', {}, `Nothing found for "${state.q}".`))
      : el('div', { class: 'empty' }, icon('notes', 'i'), el('h3', {}, 'No notes yet'), el('p', {}, 'Your notes are private to you. Write the first one.'), el('button', { class: 'btn', type: 'button', onClick: addNote }, icon('plus'), 'New note'))]));
}
function viewNotes() {
  const total = state.notes.reduce((a, n) => a + words(n.body) + words(n.title), 0);
  const last = state.notes.length ? ago([...state.notes].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))[0].updatedAt) : 'None';
  const stat = (n, l) => el('div', { class: 'stat' }, el('div', { class: 'n' }, n), el('div', { class: 'l' }, l));
  const search = el('input', { type: 'search', placeholder: 'Search notes', 'aria-label': 'Search notes', value: state.q });
  search.addEventListener('input', () => { state.q = search.value; fillNoteList(); });
  const sort = el('select', { class: 'select', 'aria-label': 'Sort notes', onChange: (e) => { state.sort = e.target.value; fillNoteList(); } },
    ...[['new', 'Newest first'], ['old', 'Oldest first'], ['az', 'Title A to Z']].map(([v, l]) => el('option', { value: v, selected: state.sort === v }, l)));
  const wrap = el('div', {},
    el('div', { class: 'page-head' }, el('h2', { class: 'page-title', tabindex: '-1' }, 'Notes'), el('button', { class: 'btn', type: 'button', onClick: addNote }, icon('plus'), 'New note')),
    el('div', { class: 'stats' }, stat(state.notes.length, 'Notes'), stat(total, 'Words'), stat(last, 'Last edit')),
    el('div', { class: 'toolbar' }, el('div', { class: 'search' }, icon('search'), search), sort),
    el('div', { class: 'notes', id: 'note-list' }));
  queueMicrotask(fillNoteList);
  return wrap;
}

/* ------------------------------------------------------------------ security center */
async function runChecks() {
  const meta = await fetch('/api/meta');
  const csp = meta.headers.get('content-security-policy');
  const cc = meta.headers.get('cache-control') || '';
  const c = [
    { ok: !/(^|;\s*)sid=/.test(document.cookie), t: 'Session cookie is hidden from page scripts', d: 'HttpOnly means injected JavaScript cannot read it.' },
    { ok: !keep.get('token'), t: 'No session token in localStorage', d: 'Anything in localStorage can be stolen by one XSS bug.' },
    { ok: !!csp && /script-src 'self'/.test(csp), t: 'Content-Security-Policy blocks inline scripts', d: csp ? 'script-src is limited to this site.' : 'No CSP header was sent.' },
    { ok: /no-store/.test(cc), t: 'API answers are never cached', d: 'Cache-Control: no-store on every /api response.' },
    { ok: !!state.csrf, t: 'Every change carries a CSRF token', d: state.csrf ? `This session token ends in ${state.csrf.slice(-4)}.` : 'No token held.' }
  ];
  state.checks = c;
}
function fillChecks() {
  const box = document.getElementById('checks'); if (!box || !state.checks) return;
  box.replaceChildren(...state.checks.map((c) => el('li', { class: c.ok ? 'pass' : 'fail' },
    el('span', { class: 'pill' }, icon(c.ok ? 'check' : 'x')),
    el('div', {}, el('b', {}, c.t, el('span', { class: 'sr' }, c.ok ? ' (passed)' : ' (failed)')), el('span', { class: 'd' }, c.d)))));
}
function viewSecurity() {
  const cur = passwordField('cur', 'Current password', 'current-password');
  let sb = null;
  const nx = passwordField('nxt', 'New password', 'new-password', () => sb?.update());
  sb = strengthBlock(() => nx.input.value, () => state.user.username);
  const form = el('form', {
    novalidate: true,
    onSubmit: async (e) => {
      e.preventDefault();
      const r = await api('POST', '/api/password', { current: cur.input.value, next: nx.input.value });
      if (!r.ok) flash('error', r.data.error || 'Could not change the password', r.data.problems);
      else { state.csrf = r.data.csrfToken; flash('ok', 'Password changed. Every other device was signed out.'); }
      render();
    }
  }, cur.wrap, nx.wrap, ...sb.nodes, el('button', { class: 'btn', type: 'submit' }, 'Change password'));
  const mins = Math.round((remainingMs() ?? 0) / 60000);
  queueMicrotask(async () => { await runChecks(); fillChecks(); });
  return el('div', {},
    el('div', { class: 'page-head' }, el('h2', { class: 'page-title', tabindex: '-1' }, 'Security')),
    el('div', { class: 'sec-grid' },
      el('div', { class: 'stack' },
        el('section', { class: 'panel' }, el('h3', {}, 'Live self-check'), el('p', { class: 'sub' }, 'These tests run in your browser right now.'), el('ul', { class: 'checks', id: 'checks' }, el('li', {}, 'Checking'))),
        el('section', { class: 'panel', 'aria-label': 'This session' }, el('h3', {}, 'This session'), el('dl', { class: 'kv' },
          el('dt', {}, 'Signed in as'), el('dd', {}, state.user.username), el('dt', {}, 'Role'), el('dd', {}, state.user.role),
          el('dt', {}, 'Idle timeout'), el('dd', {}, '30 minutes'), el('dt', {}, 'Longest session'), el('dd', {}, '8 hours'), el('dt', {}, 'Left before sign-out'), el('dd', {}, `about ${mins} min`)))),
      el('section', { class: 'panel' }, el('h3', {}, 'Change password'), el('p', { class: 'sub' }, 'You will stay signed in here. All other devices are signed out.'), flashEl(), form)));
}

/* ------------------------------------------------------------------ admin */
function fillUsers() {
  const body = document.getElementById('user-rows'); if (!body) return;
  const q = state.uq.trim().toLowerCase();
  const rows = state.users.filter((u) => !q || u.username.includes(q)).map((u) => el('tr', {},
    el('td', {}, el('span', { class: 'who' }, avatar(u.username, true), u.username)),
    el('td', {}, el('span', { class: 'badge' + (u.role === 'admin' ? ' admin' : '') }, u.role)),
    el('td', {}, new Date(u.createdAt).toLocaleDateString()),
    el('td', {}, u.id === state.user.id ? el('span', { class: 'hint' }, 'You') : el('button', { class: 'btn ghost small', type: 'button', onClick: () => changeRole(u) }, u.role === 'admin' ? 'Make user' : 'Make admin'))));
  body.replaceChildren(...(rows.length ? rows : [el('tr', {}, el('td', { colspan: '4' }, 'No users match'))]));
}
async function changeRole(u) {
  const to = u.role === 'admin' ? 'user' : 'admin';
  if (!(await confirmDialog(`Make ${u.username} ${to === 'admin' ? 'an admin' : 'a regular user'}?`, to === 'admin' ? 'Admins can see every account and change roles.' : 'They will lose access to this page.', 'Yes, change role'))) return;
  const r = await api('POST', `/api/admin/users/${u.id}/role`, { role: to });
  if (!r.ok) return toast(r.data.error || 'Could not change the role');
  await loadUsers(); fillUsers(); toast(`${u.username} is now ${to === 'admin' ? 'an admin' : 'a user'}`);
}
async function loadUsers() { const r = await api('GET', '/api/admin/users'); state.users = r.ok ? r.data.users : []; }
function viewAdmin() {
  const search = el('input', { type: 'search', placeholder: 'Search users', 'aria-label': 'Search users', value: state.uq });
  search.addEventListener('input', () => { state.uq = search.value; fillUsers(); });
  const stat = (n, l) => el('div', { class: 'stat' }, el('div', { class: 'n' }, n), el('div', { class: 'l' }, l));
  const admins = state.users.filter((u) => u.role === 'admin').length;
  queueMicrotask(fillUsers);
  return el('div', {},
    el('div', { class: 'page-head' }, el('h2', { class: 'page-title', tabindex: '-1' }, 'Users')),
    el('div', { class: 'stats' }, stat(state.users.length, 'Accounts'), stat(admins, 'Admins'), stat(state.users.length - admins, 'Regular users')),
    el('div', { class: 'toolbar' }, el('div', { class: 'search' }, icon('search'), search)),
    el('div', { class: 'panel scroll' }, el('table', {}, el('thead', {}, el('tr', {}, ...['User', 'Role', 'Joined', 'Action'].map((h) => el('th', { scope: 'col' }, h)))), el('tbody', { id: 'user-rows' }))));
}

/* ------------------------------------------------------------------ shell */
async function go(view) {
  state.view = view; state.flash = null;
  if (view === 'admin') await loadUsers();
  if (view === 'notes') await loadNotes();
  render(true);
}
function viewApp() {
  const nav = (id, label, ic, extra) => el('button', { class: 'nav-btn', type: 'button', 'aria-current': state.view === id ? 'page' : null, onClick: () => go(id) }, icon(ic), label, extra);
  const page = state.view === 'security' ? viewSecurity() : state.view === 'admin' && state.user.role === 'admin' ? viewAdmin() : viewNotes();
  return el('div', { class: 'shell' + (state.meta.vuln.length ? ' with-banner' : '') },
    el('header', { class: 'side' },
      el('h1', { class: 'brand' }, icon('lock'), 'Lockbox'),
      el('nav', { 'aria-label': 'Main' },
        nav('notes', 'Notes', 'notes', el('span', { class: 'count' }, state.notes.length)),
        nav('security', 'Security', 'shield'),
        state.user.role === 'admin' && nav('admin', 'Users', 'users')),
      el('div', { class: 'grow' }),
      sessionTimer(),
      el('div', { class: 'me' }, avatar(state.user.username), el('div', {}, el('div', { class: 'name' }, state.user.username), el('div', { class: 'role' }, state.user.role))),
      el('div', { class: 'side-actions' }, el('button', { class: 'btn small', type: 'button', 'aria-label': 'Sign out', onClick: signOut }, icon('out'), el('span', { class: 'lbl' }, 'Sign out')), themeBtn())),
    el('main', {}, page));
}

function render(focusTitle) {
  app.replaceChildren();
  if (state.meta.vuln.length) app.append(el('div', { class: 'banner', role: 'alert' }, 'Intentionally vulnerable build. Weaknesses on: ', el('code', {}, state.meta.vuln.join(', '))));
  app.append(state.user ? viewApp() : viewAuth());
  if (!state.user) document.getElementById('username')?.focus();
  else { tick(); if (focusTitle) document.querySelector('.page-title')?.focus(); }
}

(async function boot() {
  try { state.meta = await (await fetch('/api/meta')).json(); } catch { /* keep defaults */ }
  const me = await api('GET', '/api/me');
  if (me.ok) { state.user = me.data.user; state.csrf = me.data.csrfToken; await loadNotes(); }
  render();
})();
