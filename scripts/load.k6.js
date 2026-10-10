import http from "k6/http";
import { check } from "k6";

const profile = __ENV.PROFILE ?? "baseline";
const profiles = {
  baseline: { executor: "constant-vus", vus: 5, duration: "30s" },
  ramp: { executor: "ramping-vus", startVUs: 1, stages: [{ duration: "30s", target: 5 }, { duration: "30s", target: 20 }, { duration: "30s", target: 40 }, { duration: "20s", target: 0 }] },
  spike: { executor: "ramping-vus", startVUs: 2, stages: [{ duration: "10s", target: 2 }, { duration: "10s", target: 50 }, { duration: "30s", target: 50 }, { duration: "10s", target: 2 }] },
  soak: { executor: "constant-vus", vus: 10, duration: __ENV.SOAK_DURATION ?? "10m" }
};
if (!profiles[profile]) throw new Error(`Unknown PROFILE ${profile}`);
// This is a dependency-readiness gate only. It must not be read as scan/API SLO evidence.
export const options = { scenarios: { verify: { ...profiles[profile], exec: "probe" } }, thresholds: { http_req_failed: ["rate<0.01"], http_req_duration: ["p(95)<150"] } };
export function probe() {
  const base = __ENV.TARGET_URL ?? "http://127.0.0.1:33001";
  const response = http.get(`${base}/readyz`, { tags: { profile, endpoint: "dependency-readiness" } });
  let ready = false;
  try { const body = response.json(); ready = body.persistence === "postgres" && body.rate_limit === "redis"; } catch {}
  check(response, { "API dependencies report ready": (r) => r.status === 200 && ready });
}
