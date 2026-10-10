import { createClient } from "redis";
import { createServer } from "node:http";

const redis = createClient({ url: process.env.REDIS_URL ?? "redis://localhost:6379" });
redis.on("error", (error) => console.error("worker_redis_error", error.message));
await redis.connect();
const consumer = `${process.env.HOSTNAME ?? "worker"}-${process.pid}`;
await redis.xGroupCreate("shield:verify:jobs", "shield-workers", "0", { MKSTREAM: true }).catch((error) => {
  if (!String(error?.message).includes("BUSYGROUP")) throw error;
});
let active = true;
const health = createServer((_req, res) => { res.writeHead(redis.isReady ? 200 : 503, { "content-type": "application/json" }); res.end(JSON.stringify({ ok: redis.isReady, consumer })); });
health.listen(Number(process.env.WORKER_HEALTH_PORT ?? 3002), "0.0.0.0");
process.on("SIGTERM", () => { active = false; health.close(); });
process.on("SIGINT", () => { active = false; health.close(); });
while (active) {
  const streams = await redis.xReadGroup("shield-workers", consumer, [{ key: "shield:verify:jobs", id: ">" }], { COUNT: 8, BLOCK: 1000 });
  for (const stream of streams ?? []) {
    for (const item of stream.messages) {
      try {
        const payload = JSON.parse(item.message.payload ?? "{}");
        if (payload.test_failure) throw new Error("requested_test_failure");
        await redis.xAdd("shield:verify:results", "*", { job_id: item.id, status: "completed", payload: JSON.stringify(payload) });
      } catch (error) {
        await redis.xAdd("shield:verify:dead-letter", "*", { job_id: item.id, error: String(error?.message ?? error) });
      }
      await redis.xAck("shield:verify:jobs", "shield-workers", item.id);
    }
  }
}
await redis.quit();
