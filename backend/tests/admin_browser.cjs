// Admin MFA enrollment end-to-end (Playwright). CI docker job only.
// Covers the path business_browser.cjs does NOT: login as an unenrolled admin
// -> portal forces MFA -> setup -> confirm -> recovery codes -> finish ->
// re-login with TOTP -> institution modules -> /sessions diagnostic -> logout.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { chromium } = require("playwright");

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(s) {
  let bits = "";
  for (const c of s.toUpperCase()) { const v = BASE32.indexOf(c); if (v >= 0) bits += v.toString(2).padStart(5, "0"); }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, t = Math.floor(Date.now() / 1000)) {
  const counter = Math.floor(t / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", base32Decode(secret)).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = hmac.readUInt32BE(offset) & 0x7fffffff;
  return code.toString().padStart(6, "0").slice(-6);
}

(async () => {
  const fixture = JSON.parse(fs.readFileSync(process.env.RIGHTS360_E2E_FIXTURE, "utf8"));
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "block" });
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.setDefaultNavigationTimeout(15000);
    const idle = () => page.waitForFunction(() => document.documentElement.dataset.busy === "false", {}, { timeout: 15000 });
    const errors = [];
    page.on("pageerror", e => errors.push(e.message));

    await page.goto("http://127.0.0.1:8500/portal");
    const visible = sel => page.locator(sel).waitFor({ state: "visible", timeout: 15000 });

    // 1. Login as an unenrolled admin -> the portal MUST force the MFA view.
    await page.locator("#org").fill(fixture.org);
    await page.locator("#email").fill(fixture.email);
    await page.locator("#password").fill(fixture.password);
    await page.locator("#login-form button[type=submit]").click();
    await visible("#mfa-view");
    await idle();

    // 2. Setup MFA; capture the returned secret from the response.
    const setupResp = page.waitForResponse(r => new URL(r.url()).pathname === "/api/v1/auth/mfa/setup" && r.request().method() === "POST", { timeout: 15000 });
    await page.locator("#setup-password").fill(fixture.password);
    await page.locator("#setup-form button[type=submit]").click();
    const setup = await setupResp;
    assert.equal(setup.status(), 200, "mfa/setup");
    const secret = (await setup.json()).secret;
    await idle();
    await visible("#confirm-form");

    // 3. Confirm with a fresh TOTP.
    const confirmResp = page.waitForResponse(r => new URL(r.url()).pathname === "/api/v1/auth/mfa/confirm" && r.request().method() === "POST", { timeout: 15000 });
    await page.locator("#confirm-password").fill(fixture.password);
    await page.locator("#otp").fill(totp(secret));
    await page.locator("#confirm-form button[type=submit]").click();
    const confirm = await confirmResp;
    assert.equal(confirm.status(), 200, "mfa/confirm");
    assert.equal((await confirm.json()).recovery_codes.length, 10);
    await idle();
    await visible("#recovery-view");

    // 4. Acknowledge recovery codes and finish -> back to login.
    await page.locator("#saved").check();
    await page.locator("#finish").click();
    await visible("#login-view");
    await idle();

    // 5. Re-login with email + password + TOTP; capture the token.
    const reloginResp = page.waitForResponse(r => new URL(r.url()).pathname === "/api/v1/auth/login" && r.request().method() === "POST", { timeout: 15000 });
    await page.locator("#org").fill(fixture.org);
    await page.locator("#email").fill(fixture.email);
    await page.locator("#password").fill(fixture.password);
    await page.locator("#factor").selectOption("otp");
    await page.locator("#code").fill(totp(secret));
    await page.locator("#login-form button[type=submit]").click();
    const relogin = await reloginResp;
    assert.equal(relogin.status(), 200, "re-login with TOTP");
    assert.equal((await relogin.json()).mfa_required, false);
    const token = (await relogin.json()).access_token;
    await visible("#session-view");
    await idle();

    // 6. Open the institution; the artists module must be visible (entitled).
    await page.locator("#open-institution").click();
    await visible("#institution-view");
    await idle();
    await page.locator("#institution-module-list").getByText(/Artistes/).first().waitFor();

    // 7. /sessions diagnostic: admin + MFA lists active sessions without ever
    //    exposing the full token hash.
    const sess = await context.request.get("http://127.0.0.1:8500/api/v1/auth/sessions", { headers: { Authorization: "Bearer " + token } });
    assert.equal(sess.status(), 200, "GET /sessions");
    const rows = await sess.json();
    assert.ok(rows.length >= 1, "at least one active session");
    assert.ok(!("token_hash" in rows[0]), "full token hash must never be exposed");
    assert.equal(rows[0].token_suffix.length, 8);

    // 8. Logout.
    await page.locator("#institution-view [data-logout]").click();
    await visible("#login-view");
    await idle();

    assert.deepEqual(errors, []);
    console.log("Admin MFA enrollment E2E PASS: login -> forced MFA -> setup -> confirm -> recovery -> re-login(TOTP) -> institution -> /sessions -> logout");
    await context.close();
  } finally {
    await browser.close();
  }
})().catch(e => { console.error(e.message); process.exitCode = 1; });
