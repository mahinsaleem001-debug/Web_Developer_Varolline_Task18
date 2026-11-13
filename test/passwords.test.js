import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, checkPolicy } from '../src/passwords.js';
import { Limiter } from '../src/limiter.js';

test('hashes are salted and verify correctly', async () => {
  const a = await hashPassword('a long passphrase here'), b = await hashPassword('a long passphrase here');
  assert.notEqual(a, b);
  assert.ok(a.startsWith('scrypt$'));
  assert.equal(await verifyPassword('a long passphrase here', a), true);
  assert.equal(await verifyPassword('wrong', a), false);
  assert.equal(await verifyPassword('anything', 'not-a-hash'), false);
});

test('policy rejects weak passwords and accepts a good one', () => {
  for (const bad of ['a', '123456', 'password', 'Password1', 'qwertyuiop12', 'aaaaaaaaaaaa', 'abcdefghijkl', 'MyPassword12345'])
    assert.ok(checkPolicy(bad, 'someone').length > 0, bad);
  assert.ok(checkPolicy('mahin_is_here_now', 'mahin').length > 0, 'username inside');
  assert.deepEqual(checkPolicy('correct horse battery staple 42', 'mahin'), []);
  assert.ok(checkPolicy('x'.repeat(129)).length > 0);
});

test('limiter blocks after max failures and recovers after the window', () => {
  let t = 0; const l = new Limiter(3, 1000, () => t);
  for (let i = 0; i < 3; i++) l.fail('k');
  assert.ok(l.blocked('k') > 0);
  t = 1500;
  assert.equal(l.blocked('k'), 0);
  l.fail('k'); l.reset('k');
  assert.equal(l.blocked('k'), 0);
});
