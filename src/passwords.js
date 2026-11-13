import { scrypt, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const N = 16384, R = 8, P = 1, KEYLEN = 32;

/** scrypt with a random 16-byte salt. Stored as scrypt$N$r$p$salt$hash. */
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scryptAsync(password, salt, KEYLEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, salt, hash] = parts;
  const expected = Buffer.from(hash, 'base64');
  const key = await scryptAsync(password, Buffer.from(salt, 'base64'), expected.length, { N: +n, r: +r, p: +p });
  return key.length === expected.length && timingSafeEqual(key, expected);
}

/** Unsalted SHA-256. Only used by the intentionally vulnerable build ("plainhash"). */
export const weakHash = (password) => createHash('sha256').update(password).digest('hex');

export function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

const COMMON = new Set([
  '123456', '12345678', '123456789', '1234567890', 'password', 'password1', 'password123', 'qwerty', 'qwerty123',
  'qwertyuiop', 'abc123', 'letmein', 'welcome', 'welcome1', 'admin', 'admin123', 'administrator', 'iloveyou',
  'monkey', 'dragon', 'football', 'baseball', 'master', 'sunshine', 'princess', 'login', 'passw0rd', 'p@ssw0rd',
  'p@ssword', 'changeme', 'trustno1', 'whatever', 'starwars', 'shadow', 'superman', 'michael', 'charlie',
  '000000', '111111', '121212', '654321', '666666', '7777777', 'zaq12wsx', '1q2w3e4r', '1qaz2wsx', 'asdfghjkl'
]);

function hasSequence(s, len = 6) {
  let up = 1, down = 1;
  for (let i = 1; i < s.length; i++) {
    const d = s.charCodeAt(i) - s.charCodeAt(i - 1);
    up = d === 1 ? up + 1 : 1;
    down = d === -1 ? down + 1 : 1;
    if (up >= len || down >= len) return true;
  }
  return false;
}

/** Returns a list of problems. An empty list means the password is acceptable. */
export function checkPolicy(password, username = '') {
  if (typeof password !== 'string') return ['A password is required'];
  const problems = [];
  const low = password.toLowerCase();
  if (password.length < 12) problems.push('Use at least 12 characters');
  if (password.length > 128) problems.push('Use at most 128 characters');
  const stripped = low.replace(/[0-9!@#$%^&*._-]+$/, '');
  if (COMMON.has(low) || COMMON.has(stripped) || /password|qwerty|letmein/.test(low)) problems.push('This password is too common');
  if (username.length >= 3 && low.includes(username.toLowerCase())) problems.push('Do not include your username');
  if (/^(.)\1+$/.test(password)) problems.push('Do not repeat one character');
  else if (hasSequence(low)) problems.push('Avoid runs like 123456 or abcdef');
  return problems;
}
