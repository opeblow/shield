(() => {
  const params = new URLSearchParams(window.location.search);
  const title = params.get("title") ?? "";
  const text = params.get("text") ?? "";
  const url = params.get("url") ?? "";
  const payload = [title, text, url].filter(Boolean).join("\n").trim();
  const quote = document.getElementById("quote");
  const error = document.getElementById("error");
  const button = document.getElementById("check");
  if (quote && payload) quote.textContent = payload.slice(0, 2000);
  const next = `/app?text=${encodeURIComponent(payload)}`;
  if (button) {
    button.addEventListener("click", () => {
      button.disabled = true;
      window.location.href = next;
    });
  }
  const urlNext = window.location.origin + next;
  fetch("/v1/session", { credentials: "include" })
    .then((response) => (response.ok ? response.json() : Promise.reject(new Error("unauth"))))
    .then(() => { if (button) { button.textContent = "Open in Shield"; button.disabled = false; } })
    .catch(() => {
      const login = `/auth?mode=signin&next=${encodeURIComponent(urlNext)}`;
      if (button) { button.textContent = "Sign in to continue"; button.disabled = false; button.onclick = () => { window.location.href = login; }; }
    });
  if (error && !payload) {
    error.textContent = "Nothing to check. Share a message or link, then open this page again.";
    error.classList.remove("hidden");
  }
})();