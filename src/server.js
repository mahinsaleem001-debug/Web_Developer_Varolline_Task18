import { randomBytes } from 'node:crypto';
import { createApp, FLAGS } from './app.js';

const vulnerable = process.argv.includes('--vulnerable') || process.env.VULN === 'all';
const picked = (process.env.VULN || '').split(',').map((s) => s.trim()).filter((s) => FLAGS.includes(s));
const vuln = vulnerable ? FLAGS : picked;
const port = Number(process.env.PORT) || 4000;

const { app, store, createUser } = await createApp({
  vuln,
  dbFile: vuln.length ? 'data/db.vulnerable.json' : 'data/db.json',
  cookieSecure: process.env.NODE_ENV === 'production'
});

if (!store.userByName('admin')) {
  const pw = vuln.length ? 'admin' : process.env.ADMIN_PASSWORD || randomBytes(9).toString('base64url');
  await createUser('admin', pw, 'admin');
  console.log(`Created admin account. Username: admin   Password: ${pw}`);
  if (!vuln.length && !process.env.ADMIN_PASSWORD) console.log('This password is shown once. Change it after signing in.');
}

app.listen(port, () => {
  console.log(`Lockbox running at http://localhost:${port}/`);
  if (vuln.length) console.log(`WARNING: intentionally vulnerable build (${vuln.join(', ')}). Do not expose this to a network.`);
});
