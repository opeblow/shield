/*!
 * Shield fraud-warning snippet — drop-in customer protection for bank transfer pages.
 * Zero dependencies, CSP-safe (no eval), framework-agnostic. Self-authored.
 *
 *   <div id="shield-warning"></div>
 *   <script src="https://cdn.example/shield-snippet.js"></script>
 *   <script>
 *     ShieldProtect.mount("#shield-warning", {
 *       baseUrl: "https://api.shield.example",
 *       apiKey: "optional-tenant-key",     // omit for public rate-limited access
 *       context: { amount: 450000, beneficiaryAccount: "0123456789", payeeNovel: true }
 *     });
 *   </script>
 */
(function (global) {
  "use strict";

  var COPY = {
    allow: { tone: "safe", title: "This transfer looks safe", body: "No known warning signs were found. Always confirm the recipient yourself." },
    warn: { tone: "caution", title: "Be careful", body: "Some risk signals were found. Double-check the recipient before you send money." },
    review: { tone: "caution", title: "High-value transfer", body: "A large transfer like this is often used by scammers. Confirm with someone you trust." },
    delay: { tone: "danger", title: "Pause before you send", body: "This looks like a scam. Scammers rush you. Stop, verify, and talk to someone first." },
    block: { tone: "danger", title: "Do not send money", body: "This is very likely a scam. Do not send any money or share any codes." }
  };
  var COLORS = { safe: "#0b7a3b", caution: "#8a6d00", danger: "#b3261e" };
  var BACKGROUND = { safe: "#e9f7ef", caution: "#fdf6dd", danger: "#fdecea" };

  function render(target, assessment) {
    var copy = COPY[assessment.action] || COPY.warn;
    var container = document.createElement("div");
    container.setAttribute("role", assessment.action === "block" || assessment.action === "delay" ? "alert" : "status");
    container.setAttribute("data-shield-action", assessment.action);
    container.style.cssText = "border:1px solid " + COLORS[copy.tone] + ";background:" + BACKGROUND[copy.tone] +
      ";color:" + COLORS[copy.tone] + ";border-radius:8px;padding:12px 14px;font:14px/1.45 system-ui,sans-serif;margin:8px 0";
    var title = document.createElement("strong");
    title.textContent = copy.title;
    title.style.display = "block";
    title.style.marginBottom = "4px";
    var body = document.createElement("span");
    body.textContent = assessment.customer_message && assessment.customer_message.text
      ? assessment.customer_message.text
      : copy.body;
    container.appendChild(title);
    container.appendChild(body);
    target.textContent = "";
    target.appendChild(container);
  }

  function mount(selector, options) {
    var target = typeof selector === "string" ? document.querySelector(selector) : selector;
    if (!target) return Promise.reject(new Error("ShieldProtect: target element not found"));
    var opts = options || {};
    var headers = { "content-type": "application/json", accept: "application/json" };
    if (opts.apiKey) headers.authorization = "Bearer " + opts.apiKey;
    return fetch((opts.baseUrl || "").replace(/\/$/, "") + "/v1/assess", {
      method: "POST",
      headers: headers,
      body: JSON.stringify(opts.context || {}),
      credentials: "omit"
    }).then(function (response) {
      if (!response.ok) throw new Error("ShieldProtect: assessment failed (" + response.status + ")");
      return response.json();
    }).then(function (assessment) {
      render(target, assessment);
      return assessment;
    });
  }

  global.ShieldProtect = { mount: mount, version: "1.0.0" };
})(typeof window !== "undefined" ? window : globalThis);
