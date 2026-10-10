import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";

async function freePort() {
  const socket = net.createServer();
  await new Promise((resolve, reject) => socket.listen(0, "127.0.0.1", resolve).once("error", reject));
  const { port } = socket.address();
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

test("HTTP auth, CSRF, session IDOR, headers, and input validation attacks fail closed", async (t) => {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const server = spawn(process.execPath, ["dist/apps/api/src/server.js"], {
    cwd: process.cwd(),
    env: { ...process.env, NODE_ENV: "development", PORT: String(port), AUTH_SECRET: "test-auth-secret-that-is-long-enough-0001", CERTIFICATE_SECRET: "test-cert-secret-that-is-long-enough-0001" },
    stdio: "ignore"
  });
  t.after(() => { server.kill(); });
  let ready = false;
  for (let i = 0; i < 100; i += 1) {
    try { if ((await fetch(`${base}/healthz`)).ok) { ready = true; break; } } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(ready, true, "API child process starts and becomes healthy");
  const json = (path, body, cookie, origin = `${base}`) => fetch(`${base}${path}`, {
    method: "POST", headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}), ...(origin ? { origin } : {}) }, body: JSON.stringify(body), redirect: "manual"
  });
  const register = async (email) => {
    const response = await json("/v1/auth/register", { email, password: "correct horse battery" }, undefined);
    assert.equal(response.status, 201);
    const cookie = response.headers.get("set-cookie").split(";")[0];
    return cookie;
  };
  const alice = await register("alice@example.test");
  const bob = await register("bob@example.test");

  const csrf = await json("/v1/auth/logout", {}, alice, "https://attacker.example");
  assert.equal(csrf.status, 403, "cross-origin cookie-authenticated mutation is denied");
  const missingOrigin = await json("/v1/auth/logout", {}, alice, "");
  assert.equal(missingOrigin.status, 403, "cookie-authenticated mutation without Origin/Referer is denied");

  const unauthenticated = await fetch(`${base}/app`, { redirect: "manual" });
  assert.equal(unauthenticated.status, 302);
  assert.equal(unauthenticated.headers.get("location"), "/auth");

  const scan = await json("/v1/scans", { text: "Please send your OTP now immediately", language: "en" }, alice);
  assert.equal(scan.status, 200);
  const scanBody = await scan.json();
  const certificate = await json("/v1/certificates", { scan_id: scanBody.scan_id }, alice);
  assert.equal(certificate.status, 201);
  const crossUserCertificate = await json("/v1/certificates", { scan_id: scanBody.scan_id }, bob);
  assert.equal(crossUserCertificate.status, 403, "another account cannot mint a certificate for Alice's scan");

  const createKey = await json("/v1/integration/keys", { name: "Alice bank", scopes: ["scans:write"] }, alice);
  assert.equal(createKey.status, 201);
  const aliceKey = await createKey.json();
  const bobKeys = await fetch(`${base}/v1/integration/keys`, { headers: { cookie: bob } });
  assert.deepEqual((await bobKeys.json()).keys, [], "key listing is scoped to the owning account");
  const stealKey = await fetch(`${base}/v1/integration/keys/${aliceKey.id}`, { method: "DELETE", headers: { cookie: bob, origin: base } });
  assert.equal(stealKey.status, 404, "another account cannot revoke Alice's key");
  const aliceKeys = await fetch(`${base}/v1/integration/keys`, { headers: { cookie: alice } });
  assert.equal((await aliceKeys.json()).keys.length, 1);

  let finalLoginStatus = 0;
  for (let i = 0; i < 31; i += 1) {
    const response = await json("/v1/auth/login", { email: "missing@example.test", password: "incorrect" }, undefined);
    finalLoginStatus = response.status;
  }
  assert.equal(finalLoginStatus, 429, "credential stuffing from a single client is rate limited");

  const massAssignment = await json("/v1/scans", { text: "ordinary text", tenantId: "victim", isAdmin: true }, alice);
  assert.equal(massAssignment.status, 400);
  const traversal = await fetch(`${base}/%2e%2e/.env`);
  assert.notEqual(traversal.status, 200, "path traversal cannot expose environment files");
  const headers = await fetch(`${base}/healthz`);
  assert.equal(headers.headers.get("x-content-type-options"), "nosniff");
  assert.match(headers.headers.get("content-security-policy") ?? "", /default-src 'self'/);

  const smugglingResponse = await new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    let response = "";
    socket.setTimeout(2000, () => socket.destroy());
    socket.on("data", (chunk) => { response += chunk.toString("latin1"); });
    socket.on("close", () => resolve(response));
    socket.on("error", () => resolve(response));
    socket.on("connect", () => socket.write("POST /v1/auth/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nGET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
  });
  assert.match(smugglingResponse, /400 Bad Request/i, "ambiguous Content-Length and Transfer-Encoding framing is rejected by Node HTTP parser");
});
