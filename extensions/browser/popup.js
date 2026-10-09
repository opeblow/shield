const text = document.getElementById("text");
const button = document.getElementById("scan");
const status = document.getElementById("status");
const result = document.getElementById("result");
const baseInput = document.getElementById("base");
const keyInput = document.getElementById("key");

const DEFAULTS = { base: "http://localhost:3001", key: "" };
const params = new URLSearchParams(window.location.search);

chrome.storage.sync.get(DEFAULTS, (stored) => {
  baseInput.value = stored.base;
  keyInput.value = stored.key;
  const incoming = params.get("text") ?? "";
  if (incoming && !text.value) text.value = incoming.slice(0, 20000);
  updateButton();
});

function updateButton() {
  const ready = text.value.trim().length >= 2 && Boolean(baseInput.value.trim());
  if (baseInput.value.trim() && !keyInput.value.trim()) {
    status.textContent = "Submitting without an API key will be limited to anonymous scanning.";
    status.className = "";
    status.classList.remove("error");
  }
  button.disabled = !ready;
}

text.addEventListener("input", updateButton);
baseInput.addEventListener("input", () => chrome.storage.sync.set({ base: baseInput.value }));
keyInput.addEventListener("input", () => chrome.storage.sync.set({ key: keyInput.value }));

function render(data) {
  const label = ({ safe: "No scams found", caution: "Pause and check", likely_scam: "Likely scam", scam: "Strong scam signs" })[data.verdict];
  const tone = data.verdict === "safe" ? "safe" : data.verdict === "caution" ? "caution" : "scam";
  const shieldCount = data.shield?.verified_reports ?? 0;
  result.innerHTML = "";
  const line = document.createElement("p");
  line.className = "verdict " + tone;
  line.textContent = `Result: ${label}`;
  result.appendChild(line);
  if (data.reasons?.length) {
    const list = document.createElement("ul");
    for (const reason of data.reasons.slice(0, 5)) {
      const item = document.createElement("li");
      item.textContent = reason;
      list.appendChild(item);
    }
    result.appendChild(list);
  }
  status.textContent = shieldCount
    ? `Shield flagged ${shieldCount} verified report${shieldCount === 1 ? "" : "s"} matching this text.`
    : "Check complete. No verified community reports match this text.";
  status.className = "";
}

button.addEventListener("click", async () => {
  button.disabled = true;
  status.textContent = "Scanning…";
  status.className = "";
  try {
    const base = baseInput.value.trim().replace(/\/+$/, "");
    const key = (keyInput.value || "").trim();
    const response = await fetch(`${base}/v1/integrations/scan`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(key ? { "x-api-key": key } : {})
      },
      body: JSON.stringify({ text: text.value.trim(), mode: "fast" })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail ?? data.title ?? `Request failed (${response.status}).`);
    render(data);
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Check failed. Confirm the base URL points at a Shield server.";
    status.classList.add("error");
  } finally {
    updateButton();
  }
});