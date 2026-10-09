import { spawn } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const edge = process.env.EDGE_PATH ?? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const port = 9337;
const profile = mkdtempSync(join(tmpdir(), "shield-edge-"));
const browser = spawn(edge, [
  "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
  `--remote-debugging-port=${port}`, "--remote-allow-origins=*", `--user-data-dir=${profile}`, "about:blank"
], { windowsHide: true, stdio: "ignore" });

class DevTools {
  nextId = 0;
  pending = new Map();
  constructor(socket) {
    this.socket = socket;
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (!message.id) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
    });
  }
  send(method, params = {}) {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`DevTools timed out: ${method}`));
      }, 5000);
      this.pending.set(id, {
        resolve: (value) => { clearTimeout(timeout); resolve(value); },
        reject: (error) => { clearTimeout(timeout); reject(error); }
      });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }
}

async function waitForDebugPort() {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try { return await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(); }
    catch { await new Promise((resolve) => setTimeout(resolve, 150)); }
  }
  throw new Error("Edge remote debugging endpoint did not start");
}

async function capture(devtools, width, height, mobile, destination) {
  await devtools.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile });
  await devtools.send("Page.enable");
  await devtools.send("Page.navigate", { url: "http://localhost:3001/" });
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    const state = await devtools.send("Runtime.evaluate", { expression: "document.readyState", returnByValue: true });
    if (state.result.value === "complete") { ready = true; break; }
  }
  if (!ready) throw new Error(`Page did not finish loading at ${width}x${height}`);
  await new Promise((resolve) => setTimeout(resolve, 250));
  const { result } = await devtools.send("Runtime.evaluate", { expression: "({width:innerWidth, height:innerHeight, documentWidth:document.documentElement.scrollWidth})", returnByValue: true });
  const screenshot = await devtools.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, fromSurface: true });
  writeFileSync(destination, Buffer.from(screenshot.data, "base64"));
  process.stdout.write(`${JSON.stringify({ file: destination, ...result.value })}\n`);
}

try {
  const targets = await waitForDebugPort();
  const page = targets.find((target) => target.type === "page");
  if (!page?.webSocketDebuggerUrl) throw new Error("Edge did not expose a page target");
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  const devtools = new DevTools(socket);
  await capture(devtools, 390, 844, true, "docs/screenshots/shield-mobile.png");
  await capture(devtools, 1440, 1100, false, "docs/screenshots/shield-desktop.png");
  socket.close();
} finally {
  browser.kill();
}
