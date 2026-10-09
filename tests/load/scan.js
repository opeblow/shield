import http from "k6/http";
import { check, sleep } from "k6";

// Load profile for the public scan path. Run against a staging deployment:
//   k6 run -e BASE_URL=https://staging.shield.example tests/load/scan.js -e API_KEY=...
const BASE_URL = __ENV.BASE_URL || "http://localhost:3001";
const API_KEY = __ENV.API_KEY || "";

export const options = {
  scenarios: {
    steady: { executor: "ramping-vus", startVUs: 5, stages: [{ duration: "30s", target: 50 }, { duration: "1m", target: 50 }, { duration: "20s", target: 0 }] }
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<800", "p(99)<1500"],
    checks: ["rate>0.99"]
  }
};

const samples = [
  "Please send your OTP now to complete the transfer urgently",
  "Congratulations you have won a prize, pay a small fee to claim it",
  "Your account was debited NGN 5,000.00 reference 123456",
  "This is your boss, send the money now and do not tell anyone"
];

export default function () {
  const headers = { "content-type": "application/json" };
  if (API_KEY) headers.authorization = `Bearer ${API_KEY}`;
  const body = JSON.stringify({ text: samples[Math.floor(Math.random() * samples.length)], language: "en", mode: "fast" });
  const response = http.post(`${BASE_URL}/v1/scans`, body, { headers });
  check(response, { "status 200": (r) => r.status === 200, "has verdict": (r) => r.json("verdict") !== undefined });
  sleep(1);
}
