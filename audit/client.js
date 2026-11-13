/** A tiny HTTP client with a cookie jar, so attacks behave like a browser (or like an attacker's script). */
export class Client {
  constructor(base) { this.base = base; this.jar = new Map(); this.csrf = null; }

  async req(method, path, { json, headers = {}, cookies = true } = {}) {
    const h = { ...headers };
    if (json !== undefined) h['content-type'] = 'application/json';
    if (cookies && this.jar.size && !h.cookie) h.cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const t0 = performance.now();
    const res = await fetch(this.base + path, { method, headers: h, body: json !== undefined ? JSON.stringify(json) : undefined, redirect: 'manual' });
    const ms = performance.now() - t0;
    const setCookies = res.headers.getSetCookie?.() ?? [];
    for (const c of setCookies) {
      const pair = c.split(';')[0];
      const i = pair.indexOf('=');
      const k = pair.slice(0, i), v = pair.slice(i + 1);
      if (/max-age=0/i.test(c) || v === '') this.jar.delete(k); else this.jar.set(k, v);
    }
    const text = await res.text();
    let body = text;
    try { body = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, body, headers: res.headers, setCookies, ms };
  }

  /** A same-origin API call, exactly as the real front end makes it. */
  api(method, path, json) {
    const headers = { origin: this.base };
    if (this.csrf) headers['x-csrf-token'] = this.csrf;
    return this.req(method, path, { json, headers });
  }

  async login(username, password) {
    const r = await this.req('POST', '/api/login', { json: { username, password }, headers: { origin: this.base } });
    if (r.status === 200) this.csrf = r.body.csrfToken;
    return r;
  }
}
