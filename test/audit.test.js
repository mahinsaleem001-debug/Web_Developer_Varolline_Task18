import { test } from 'node:test';
import assert from 'node:assert/strict';
import { attacks, runAttack } from '../audit/attacks.js';

// Every attack must succeed against the build with that weakness, and fail against the normal build.
for (const a of attacks) {
  test(`${a.id} ${a.name}: works before the fix`, async () => {
    const r = await runAttack(a, a.flags);
    assert.equal(r.exploited, true, r.evidence);
  });
  test(`${a.id} ${a.name}: blocked after the fix`, async () => {
    const r = await runAttack(a, []);
    assert.equal(r.exploited, false, r.evidence);
  });
}
