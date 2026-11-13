import { createApp } from '../src/app.js';
import { Client } from './client.js';
import { weakHash } from '../src/passwords.js';

const PW = 'correct horse battery staple 42';
const median = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const EVIL = 'http://evil.example';

/**
 * Every attack returns { exploited, evidence }.
 *   flags  : the single weakness the "before" build switches on
 *   limits : rate-limit overrides so one attack does not trip another's limiter
 */
export const attacks = [
  {
    id: 'A1', category: 'Weak password rules', name: 'Register with weak passwords ("a", "123456", "password", username as password)',
    flags: ['weakpw'], fix: 'Server-side policy: 12 to 128 characters, common-password and pattern blocklist, no username inside.',
    async run({ c }) {
      const tries = [['u_a', 'a'], ['u_num', '123456'], ['u_pw', 'password'], ['u_same', 'u_same']];
      const accepted = [];
      for (const [u, p] of tries) { const r = await c.req('POST', '/api/register', { json: { username: u, password: p }, headers: { origin: c.base } }); if (r.status === 201) accepted.push(p); }
      return { exploited: accepted.length > 0, evidence: `${accepted.length} of ${tries.length} weak passwords accepted` };
    }
  },
  {
    id: 'A2', category: 'Broken access control', name: 'Mass assignment: sign up with {"role":"admin"} and open the admin API',
    flags: ['privesc'], fix: 'Registration ignores every field except username and password. Role is always "user".',
    async run({ c }) {
      const reg = await c.req('POST', '/api/register', { json: { username: 'mallory', password: PW, role: 'admin' }, headers: { origin: c.base } });
      await c.login('mallory', PW);
      const r = await c.api('GET', '/api/admin/users');
      return { exploited: r.status === 200, evidence: `register ${reg.status}, GET /api/admin/users -> ${r.status}` };
    }
  },
  {
    id: 'A3', category: 'Broken access control', name: 'Vertical escalation: normal user calls admin endpoints',
    flags: ['privesc'], fix: 'requireAdmin middleware checks the role on every admin route.',
    async run({ c, createUser }) {
      await createUser('victim_admin', PW, 'admin'); await createUser('bob', PW); await createUser('pal', PW);
      await c.login('bob', PW);
      const list = await c.api('GET', '/api/admin/users');
      const promote = await c.api('POST', '/api/admin/users/3/role', { role: 'admin' });
      return { exploited: list.status === 200 || promote.status === 200, evidence: `list -> ${list.status}, promote -> ${promote.status}` };
    }
  },
  {
    id: 'A4', category: 'Broken access control', name: 'IDOR: read, edit and delete another user’s note by guessing its id',
    flags: ['idor'], fix: 'Every note route checks note.ownerId === session user. Foreign notes answer 404.',
    async run({ base, createUser }) {
      await createUser('alice', PW); await createUser('eve', PW);
      const a = new Client(base), e = new Client(base);
      await a.login('alice', PW); await e.login('eve', PW);
      const made = await a.api('POST', '/api/notes', { title: 'Alice private', body: 'bank pin 4921' });
      const id = made.body.note.id;
      const read = await e.api('GET', `/api/notes/${id}`);
      const edit = await e.api('PUT', `/api/notes/${id}`, { title: 'pwned', body: 'x' });
      const del = await e.api('DELETE', `/api/notes/${id}`);
      const anon = await new Client(base).req('GET', '/api/notes');
      const hit = [read, edit, del].filter((r) => r.status === 200).length;
      return { exploited: hit > 0, evidence: `read ${read.status}, edit ${edit.status}, delete ${del.status}; anonymous list -> ${anon.status}` };
    }
  },
  {
    id: 'A5', category: 'Username enumeration', name: 'Login answers differently for unknown user vs wrong password',
    flags: ['enum'], fix: 'One message and one status (401 "Invalid username or password") for both cases.',
    async run({ c, createUser }) {
      await createUser('realuser', PW);
      const known = await c.req('POST', '/api/login', { json: { username: 'realuser', password: 'wrong-guess-1' }, headers: { origin: c.base } });
      const unknown = await c.req('POST', '/api/login', { json: { username: 'nobody_here', password: 'wrong-guess-1' }, headers: { origin: c.base } });
      const differ = known.status !== unknown.status || JSON.stringify(known.body) !== JSON.stringify(unknown.body);
      return { exploited: differ, evidence: `existing: ${known.status} "${known.body.error}" | missing: ${unknown.status} "${unknown.body.error}"` };
    }
  },
  {
    id: 'A6', category: 'Username enumeration', name: 'Timing: unknown usernames answer faster than real ones (no hash work)',
    flags: ['enum'], limits: { loginIp: 1000, loginUser: 1000 }, fix: 'Unknown usernames still run one scrypt verification against a dummy hash.',
    async run({ c, createUser }) {
      const n = 12, known = [], unknown = [];
      for (let i = 0; i < n; i++) await createUser(`known${i}`, PW);
      for (let i = 0; i < n; i++) {
        const k = await c.req('POST', '/api/login', { json: { username: `known${i}`, password: 'not-the-password' }, headers: { origin: c.base } });
        const u = await c.req('POST', '/api/login', { json: { username: `ghost${i}`, password: 'not-the-password' }, headers: { origin: c.base } });
        known.push(k.ms); unknown.push(u.ms);
      }
      const mk = median(known), mu = median(unknown);
      return { exploited: mk > mu * 2 && mk - mu > 10, evidence: `median existing ${mk.toFixed(0)} ms vs missing ${mu.toFixed(0)} ms` };
    }
  },
  {
    id: 'A7', category: 'Username enumeration', name: 'Bulk probing of /api/register to list taken usernames (30 probes)',
    flags: ['norate'], fix: 'Sign-ups are rate limited per IP (10 per hour). A single probe still reveals one name; see README.',
    async run({ c, createUser }) {
      for (let i = 0; i < 30; i++) await createUser(`taken${i}`, PW);
      let answered = 0;
      for (let i = 0; i < 30; i++) {
        const r = await c.req('POST', '/api/register', { json: { username: `taken${i}`, password: PW }, headers: { origin: c.base } });
        if (r.status === 409) answered++;
      }
      return { exploited: answered >= 30, evidence: `${answered} of 30 probes got a "taken" answer` };
    }
  },
  {
    id: 'A8', category: 'Missing CSRF protection', name: 'Forged cross-site POST using the victim’s cookie (Origin: evil.example, no token)',
    flags: ['csrf'], fix: 'Origin check plus a per-session CSRF token in the X-CSRF-Token header; cookie is SameSite=Strict.',
    async run({ base, createUser }) {
      await createUser('carol', PW);
      const v = new Client(base); await v.login('carol', PW);
      const forged = await v.req('POST', '/api/notes', { json: { title: 'planted by attacker', body: '' }, headers: { origin: EVIL } });
      const noToken = await v.req('POST', '/api/notes', { json: { title: 'no token', body: '' }, headers: { origin: base } });
      const pw = await v.req('POST', '/api/password', { json: { current: PW, next: 'attacker chosen password 99' }, headers: { origin: EVIL, 'sec-fetch-site': 'cross-site' } });
      return { exploited: forged.status === 201 || noToken.status === 201 || pw.status === 200, evidence: `evil origin -> ${forged.status}, same origin without token -> ${noToken.status}, password change -> ${pw.status}` };
    }
  },
  {
    id: 'A9', category: 'Insecure token storage', name: 'Session cookie flags and token exposure in the login response',
    flags: ['cookieflags'], fix: 'Cookie is HttpOnly, SameSite=Strict (and Secure in production). The token is never in the response body.',
    async run({ c, createUser }) {
      await createUser('dave', PW);
      const r = await c.login('dave', PW);
      const cookie = r.setCookies.find((x) => x.startsWith('sid=')) || '';
      const problems = [];
      if (!/httponly/i.test(cookie)) problems.push('no HttpOnly');
      if (!/samesite/i.test(cookie)) problems.push('no SameSite');
      if (r.body.token) problems.push('token in JSON body');
      const bearer = r.body.token ? await new Client(c.base).req('GET', '/api/me', { headers: { authorization: `Bearer ${r.body.token}` } }) : null;
      if (bearer && bearer.status === 200) problems.push('Bearer token accepted');
      return { exploited: problems.length > 0, evidence: problems.length ? problems.join(', ') : 'HttpOnly + SameSite=Strict, no token in body' };
    }
  },
  {
    id: 'A10', category: 'Insecure token storage', name: 'Session fixation: attacker plants a session id, victim logs in, attacker reuses it',
    flags: ['fixation'], fix: 'A fresh random session id is issued at every login and any id sent by the client is ignored.',
    async run({ base, createUser }) {
      await createUser('erin', PW);
      const planted = 'attackerChosenSessionId1234567890';
      const victim = new Client(base); victim.jar.set('sid', planted);
      await victim.login('erin', PW);
      const attacker = new Client(base); attacker.jar.set('sid', planted);
      const r = await attacker.req('GET', '/api/me');
      return { exploited: r.status === 200, evidence: `attacker GET /api/me with the planted id -> ${r.status}` };
    }
  },
  {
    id: 'A11', category: 'Insecure token storage', name: 'Stolen session id still works after the user logs out',
    flags: ['nologout'], fix: 'Logout deletes the session on the server, so a copied cookie is dead.',
    async run({ base, createUser }) {
      await createUser('frank', PW);
      const v = new Client(base); await v.login('frank', PW);
      const stolen = v.jar.get('sid');
      await v.api('POST', '/api/logout');
      const thief = new Client(base); thief.jar.set('sid', stolen);
      const r = await thief.req('GET', '/api/me');
      return { exploited: r.status === 200, evidence: `reused cookie after logout -> ${r.status}` };
    }
  },
  {
    id: 'A12', category: 'Insecure token storage', name: 'Session never expires (idle for 2 hours, then 9 hours)',
    flags: ['noexpiry'], fix: 'Idle timeout 30 minutes and absolute lifetime 8 hours, checked on every request.',
    async run({ base, createUser, clock }) {
      await createUser('gina', PW);
      const v = new Client(base); await v.login('gina', PW);
      clock.offset += 2 * 3600e3;
      const idle = await v.req('GET', '/api/me');
      clock.offset += 7 * 3600e3;
      const abs = await v.req('GET', '/api/me');
      return { exploited: idle.status === 200 || abs.status === 200, evidence: `after 2 h idle -> ${idle.status}, after 9 h -> ${abs.status}` };
    }
  },
  {
    id: 'A13', category: 'Weak password rules', name: 'Online brute force: 40 wrong guesses against one account, then the right one',
    flags: ['norate'], fix: 'Failed logins are counted per IP and username: 5 failures block that pair for 15 minutes (429).',
    async run({ c, createUser }) {
      await createUser('henry', PW);
      let firstBlock = null;
      for (let i = 1; i <= 40; i++) {
        const r = await c.req('POST', '/api/login', { json: { username: 'henry', password: `guess-${i}` }, headers: { origin: c.base } });
        if (r.status === 429 && firstBlock === null) firstBlock = i;
      }
      const last = await c.req('POST', '/api/login', { json: { username: 'henry', password: PW }, headers: { origin: c.base } });
      return { exploited: firstBlock === null, evidence: firstBlock === null ? `no limit: 40 guesses answered, right password then -> ${last.status}` : `blocked with 429 at guess ${firstBlock}; right password during lockout -> ${last.status}` };
    }
  },
  {
    id: 'A14', category: 'Weak password rules', name: 'Stolen database: how fast can the stored password hashes be cracked?',
    flags: ['plainhash'], fix: 'scrypt (N=16384) with a random 16-byte salt per user, verified in constant time.',
    async run({ store, createUser }) {
      await createUser('ivy', 'sunshine2026!');
      const hash = store.userByName('ivy').hash;
      if (hash.startsWith('scrypt$')) return { exploited: false, evidence: `stored as ${hash.split('$').slice(0, 4).join('$')}$salt$hash (salted, slow)` };
      const list = ['123456', 'password', 'qwerty', 'sunshine2026!'];
      const t0 = performance.now();
      const cracked = list.find((w) => weakHash(w) === hash);
      return { exploited: !!cracked, evidence: `unsalted SHA-256 cracked to "${cracked}" in ${(performance.now() - t0).toFixed(1)} ms` };
    }
  },
  {
    id: 'A15', category: 'Insecure token storage', name: 'No Content-Security-Policy: injected script can read the token (XSS exposure)',
    flags: ['xss'], fix: 'CSP blocks inline scripts, the UI renders notes as text, and the token lives in an HttpOnly cookie.',
    async run({ c }) {
      const r = await c.req('GET', '/');
      const csp = r.headers.get('content-security-policy');
      return { exploited: !csp, evidence: csp ? 'CSP present: script-src \'self\' (inline scripts blocked)' : 'no Content-Security-Policy header' };
    }
  }
];

/** Boot a fresh in-memory server, run one attack, shut the server down. */
export async function runAttack(attack, flags) {
  const clock = { offset: 0 };
  const { app, store, createUser } = await createApp({
    vuln: flags, cookieSecure: true, now: () => Date.now() + clock.offset, limits: attack.limits
  });
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    return await attack.run({ base, c: new Client(base), store, createUser, clock });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    server.closeAllConnections?.();
  }
}
