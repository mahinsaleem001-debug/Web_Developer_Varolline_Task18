import fs from 'node:fs';
import path from 'node:path';

/** In-memory data with optional JSON file persistence. Sessions are never written to disk. */
export class Store {
  constructor(file = null) {
    this.file = file;
    this.users = new Map();     // id -> user
    this.notes = new Map();     // id -> note
    this.sessions = new Map();  // sha256(session id) -> record
    this.nextUser = 1;
    this.nextNote = 1;
    if (file && fs.existsSync(file)) {
      const d = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const u of d.users) this.users.set(u.id, u);
      for (const n of d.notes) this.notes.set(n.id, n);
      this.nextUser = d.nextUser; this.nextNote = d.nextNote;
    }
  }
  persist() {
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ users: [...this.users.values()], notes: [...this.notes.values()], nextUser: this.nextUser, nextNote: this.nextNote }, null, 2));
    fs.renameSync(tmp, this.file);
  }
  userById(id) { return this.users.get(id) || null; }
  userByName(name) { const n = String(name).toLowerCase(); for (const u of this.users.values()) if (u.username === n) return u; return null; }
  addUser({ username, hash, role = 'user' }) {
    const u = { id: this.nextUser++, username: String(username).toLowerCase(), hash, role, createdAt: new Date().toISOString() };
    this.users.set(u.id, u); this.persist(); return u;
  }
  addNote({ ownerId, title, body }) {
    const t = new Date().toISOString();
    const n = { id: this.nextNote++, ownerId, title, body, createdAt: t, updatedAt: t };
    this.notes.set(n.id, n); this.persist(); return n;
  }
  revokeUserSessions(userId) {
    for (const [k, s] of this.sessions) if (s.userId === userId) this.sessions.delete(k);
  }
}
