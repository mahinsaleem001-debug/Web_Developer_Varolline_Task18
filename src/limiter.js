/** Counts failures per key inside a sliding window. In memory, so it resets on restart. */
export class Limiter {
  constructor(max, windowMs, now = Date.now) {
    this.max = max; this.windowMs = windowMs; this.now = now; this.hits = new Map();
  }
  #recent(key) {
    const t = this.now();
    const list = (this.hits.get(key) || []).filter((x) => t - x < this.windowMs);
    if (list.length) this.hits.set(key, list); else this.hits.delete(key);
    return list;
  }
  /** Seconds until the key may try again, or 0 when it is allowed. */
  blocked(key) {
    const list = this.#recent(key);
    return list.length >= this.max ? Math.max(1, Math.ceil((list[0] + this.windowMs - this.now()) / 1000)) : 0;
  }
  fail(key) { const list = this.#recent(key); list.push(this.now()); this.hits.set(key, list); }
  reset(key) { this.hits.delete(key); }
}
