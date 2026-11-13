import express from 'express';
import { randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { Store } from './store.js';
import { hashPassword, verifyPassword, weakHash, checkPolicy, safeEqual } from './passwords.js';
import { Limiter } from './limiter.js';

/**
 * Each flag switches ONE weakness back on. The default build has none of them.
 * They exist so the audit can prove every attack works before the fix and fails after it.
 * Never run a real deployment with any of these.
 */
export const FLAGS = ['weakpw', 'plainhash', 'enum', 'idor', 'privesc', 'csrf', 'cookieflags', 'fixation', 'nologout', 'noexpiry', 'norate', 'xss'];

const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const IDLE_MS = 30 * 60 * 1000;      // log out after 30 minutes of inactivity
const ABSOLUTE_MS = 8 * 60 * 60 * 1000; // and never keep a session longer than 8 hours

const sidHash = (id) => createHash('sha256').update(id).digest('hex');
const newToken = (n = 32) => randomBytes(n).toString('base64url');

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export async function createApp(opts = {}) {
  const vuln = new Set(opts.vuln || []);
  const store = opts.store || new Store(opts.dbFile || null);
  const now = opts.now || Date.now;
  const lim = { loginUser: 5, loginIp: 50, register: 10, windowMs: 15 * 60 * 1000, registerWindowMs: 60 * 60 * 1000, ...opts.limits };
  const loginByUser = new Limiter(lim.loginUser, lim.windowMs, now);
  const loginByIp = new Limiter(lim.loginIp, lim.windowMs, now);
  const registerByIp = new Limiter(lim.register, lim.registerWindowMs, now);
  // Unknown usernames still pay for one scrypt run, so response time does not reveal who exists.
  const dummyHash = await hashPassword('dummy-password-used-for-timing-only');

  const makeHash = (pw) => (vuln.has('plainhash') ? weakHash(pw) : hashPassword(pw));
  const checkHash = async (pw, stored) => (stored.startsWith('scrypt$') ? verifyPassword(pw, stored) : safeEqual(weakHash(pw), stored));
  const createUser = async (username, password, role = 'user') => store.addUser({ username, hash: await makeHash(password), role });

  const app = express();
  app.disable('x-powered-by');
  const ah = (fn) => (req, res, next) => fn(req, res, next).catch(next);
  const ipOf = (req) => req.socket.remoteAddress || 'unknown';

  /* ---------------------------------------------------------------- headers */
  app.use((req, res, next) => {
    if (!vuln.has('xss')) {
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'no-referrer');
    }
    if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(express.json({ limit: '20kb' }));

  /* --------------------------------------------------------------- sessions */
  app.use((req, res, next) => {
    req.session = null; req.user = null;
    let raw = parseCookies(req).sid;
    if (!raw && vuln.has('cookieflags')) {
      const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
      if (m) raw = m[1]; // only the weak build accepts a token from JavaScript-readable storage
    }
    if (!raw) return next();
    const key = sidHash(raw);
    const rec = store.sessions.get(key);
    if (!rec) return next();
    const t = now();
    if (!vuln.has('noexpiry') && (t - rec.lastSeen > IDLE_MS || t - rec.createdAt > ABSOLUTE_MS)) {
      store.sessions.delete(key);
      return next();
    }
    const user = store.userById(rec.userId);
    if (!user) { store.sessions.delete(key); return next(); }
    rec.lastSeen = t;
    // Lets the page show an honest countdown. It is a duration, so the browser clock does not matter.
    res.setHeader('X-Session-Remaining', String(Math.max(0, Math.min(IDLE_MS, rec.createdAt + ABSOLUTE_MS - t))));
    req.session = { raw, key, rec }; req.user = user;
    next();
  });

  function startSession(req, res, userId) {
    let raw = newToken();
    const offered = parseCookies(req).sid;
    // Fixation flaw: keep whatever id the browser already holds. The fix is to always issue a fresh one.
    if (vuln.has('fixation') && offered && /^[\w-]{8,128}$/.test(offered)) raw = offered;
    else if (req.session) store.sessions.delete(req.session.key);
    const rec = { userId, csrf: newToken(24), createdAt: now(), lastSeen: now() };
    store.sessions.set(sidHash(raw), rec);
    const flags = vuln.has('cookieflags') ? '' : '; HttpOnly; SameSite=Strict' + (opts.cookieSecure ? '; Secure' : '');
    res.append('Set-Cookie', `sid=${raw}; Path=/${flags}`);
    res.setHeader('X-Session-Remaining', String(IDLE_MS));
    return { raw, rec };
  }
  const clearCookie = (res) => res.append('Set-Cookie', 'sid=; Path=/; Max-Age=0');

  /* ------------------------------------------------------------------- CSRF */
  app.use('/api', (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || vuln.has('csrf')) return next();
    const origin = req.get('origin');
    if (origin) {
      let host = null;
      try { host = new URL(origin).host; } catch { /* malformed */ }
      if (host !== req.get('host')) return res.status(403).json({ error: 'Cross-site request blocked' });
    } else if (req.get('sec-fetch-site') === 'cross-site') {
      return res.status(403).json({ error: 'Cross-site request blocked' });
    }
    if (req.session) {
      const token = req.get('x-csrf-token');
      if (!token || !safeEqual(token, req.session.rec.csrf)) return res.status(403).json({ error: 'Missing or wrong CSRF token' });
    }
    next();
  });

  const requireUser = (req, res, next) => (req.user ? next() : res.status(401).json({ error: 'Sign in first' }));
  const requireAdmin = (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Sign in first' });
    // Privilege flaw: the weak build only checks that someone is signed in.
    if (!vuln.has('privesc') && req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
    next();
  };
  const publicUser = (u) => ({ id: u.id, username: u.username, role: u.role });

  /* ------------------------------------------------------------------- auth */
  app.get('/api/meta', (req, res) => res.json({ vuln: [...vuln] }));

  app.post('/api/register', ah(async (req, res) => {
    const { username, password } = req.body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Username and password are required' });
    if (!vuln.has('norate')) {
      const wait = registerByIp.blocked(ipOf(req));
      if (wait) return res.set('Retry-After', String(wait)).status(429).json({ error: 'Too many sign-up attempts. Try again later.' });
      registerByIp.fail(ipOf(req));
    }
    const name = username.trim().toLowerCase();
    if (!(vuln.has('weakpw') ? name.length > 0 : /^[a-z0-9_]{3,32}$/.test(name))) {
      return res.status(400).json({ error: 'Username must be 3 to 32 characters: letters, numbers or underscore' });
    }
    const problems = vuln.has('weakpw') ? (password.length ? [] : ['A password is required']) : checkPolicy(password, name);
    if (problems.length) return res.status(400).json({ error: 'Password is too weak', problems });
    if (store.userByName(name)) return res.status(409).json({ error: 'That username is taken' });
    // Mass-assignment flaw: the weak build copies "role" straight from the request body.
    const role = vuln.has('privesc') && req.body.role ? String(req.body.role) : 'user';
    const user = await createUser(name, password, role);
    res.status(201).json({ user: publicUser(user) });
  }));

  app.post('/api/login', ah(async (req, res) => {
    const { username, password } = req.body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Username and password are required' });
    const name = username.trim().toLowerCase();
    const userKey = `${ipOf(req)}|${name}`;
    if (!vuln.has('norate')) {
      const wait = Math.max(loginByUser.blocked(userKey), loginByIp.blocked(ipOf(req)));
      if (wait) return res.set('Retry-After', String(wait)).status(429).json({ error: 'Too many attempts. Try again later.' });
    }
    const user = store.userByName(name);
    let ok;
    if (vuln.has('enum')) {
      // Enumeration flaw: different answer, and no hashing work, for names that do not exist.
      if (!user) return res.status(404).json({ error: 'No such user' });
      ok = await checkHash(password, user.hash);
      if (!ok) return res.status(401).json({ error: 'Wrong password' });
    } else {
      ok = await checkHash(password, user ? user.hash : dummyHash) && !!user;
    }
    if (!ok) {
      loginByUser.fail(userKey); loginByIp.fail(ipOf(req));
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    loginByUser.reset(userKey);
    const { raw, rec } = startSession(req, res, user.id);
    const out = { user: publicUser(user), csrfToken: rec.csrf };
    if (vuln.has('cookieflags')) out.token = raw; // token in the body invites storage in localStorage
    res.json(out);
  }));

  app.post('/api/logout', (req, res) => {
    // Logout flaw: the weak build forgets the cookie but leaves the session alive on the server.
    if (req.session && !vuln.has('nologout')) store.sessions.delete(req.session.key);
    clearCookie(res);
    res.json({ ok: true });
  });

  app.get('/api/me', (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Not signed in' });
    res.json({ user: publicUser(req.user), csrfToken: req.session.rec.csrf });
  });

  app.post('/api/password', requireUser, ah(async (req, res) => {
    const { current, next } = req.body ?? {};
    if (typeof current !== 'string' || typeof next !== 'string') return res.status(400).json({ error: 'Current and new password are required' });
    if (!(await checkHash(current, req.user.hash))) return res.status(403).json({ error: 'Current password is wrong' });
    const problems = vuln.has('weakpw') ? [] : checkPolicy(next, req.user.username);
    if (problems.length) return res.status(400).json({ error: 'New password is too weak', problems });
    req.user.hash = await makeHash(next);
    store.persist();
    store.revokeUserSessions(req.user.id); // a password change signs out every other device
    const { rec } = startSession(req, res, req.user.id);
    res.json({ ok: true, csrfToken: rec.csrf });
  }));

  /* ------------------------------------------------------------------ notes */
  const own = (req, n) => vuln.has('idor') || (n && n.ownerId === req.user.id);
  const cleanNote = (b) => {
    const title = typeof b?.title === 'string' ? b.title.trim() : '';
    const body = typeof b?.body === 'string' ? b.body : '';
    if (!title || title.length > 100 || body.length > 5000) return null;
    return { title, body };
  };

  app.get('/api/notes', requireUser, (req, res) => {
    res.json({ notes: [...store.notes.values()].filter((n) => n.ownerId === req.user.id).sort((a, b) => b.id - a.id) });
  });
  app.post('/api/notes', requireUser, (req, res) => {
    const c = cleanNote(req.body);
    if (!c) return res.status(400).json({ error: 'A title (up to 100 characters) is required' });
    res.status(201).json({ note: store.addNote({ ownerId: req.user.id, ...c }) });
  });
  // Access-control flaw: the weak build looks notes up by id and never asks who owns them.
  app.get('/api/notes/:id', requireUser, (req, res) => {
    const n = store.notes.get(Number(req.params.id));
    if (!n || !own(req, n)) return res.status(404).json({ error: 'Note not found' });
    res.json({ note: n });
  });
  app.put('/api/notes/:id', requireUser, (req, res) => {
    const n = store.notes.get(Number(req.params.id));
    if (!n || !own(req, n)) return res.status(404).json({ error: 'Note not found' });
    const c = cleanNote(req.body);
    if (!c) return res.status(400).json({ error: 'A title (up to 100 characters) is required' });
    Object.assign(n, c, { updatedAt: new Date().toISOString() }); store.persist();
    res.json({ note: n });
  });
  app.delete('/api/notes/:id', requireUser, (req, res) => {
    const n = store.notes.get(Number(req.params.id));
    if (!n || !own(req, n)) return res.status(404).json({ error: 'Note not found' });
    store.notes.delete(n.id); store.persist();
    res.json({ ok: true });
  });

  /* ------------------------------------------------------------------ admin */
  app.get('/api/admin/users', requireAdmin, (req, res) => {
    res.json({ users: [...store.users.values()].map((u) => ({ ...publicUser(u), createdAt: u.createdAt })) });
  });
  app.post('/api/admin/users/:id/role', requireAdmin, (req, res) => {
    const u = store.userById(Number(req.params.id));
    const role = req.body?.role;
    if (!u) return res.status(404).json({ error: 'User not found' });
    if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Role must be user or admin' });
    if (u.id === req.user.id) return res.status(400).json({ error: 'You cannot change your own role' });
    u.role = role; store.persist();
    res.json({ user: publicUser(u) });
  });

  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
  app.use(express.static(PUBLIC));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  });

  return { app, store, createUser, vuln };
}
