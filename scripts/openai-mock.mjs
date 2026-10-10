import { createServer } from "node:http";

let mode = "ok";
const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/healthz") { res.writeHead(200); res.end("ok"); return; }
  if (url.pathname === "/__control" && req.method === "POST") {
    mode = url.searchParams.get("mode") ?? "ok";
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ mode })); return;
  }
  if (req.url !== "/v1/chat/completions") { res.writeHead(404); res.end(); return; }
  if (mode === "timeout") { await new Promise((resolve) => setTimeout(resolve, 8_000)); if (res.destroyed) return; }
  if (mode === "error") { res.writeHead(503); res.end(JSON.stringify({ error: "injected failure" })); return; }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ scam: false, scam_types: [], confidence: 0.6, reasons: [] }) } }] }));
});
server.listen(Number(process.env.OPENAI_MOCK_PORT ?? 4010), "0.0.0.0");
