const els = {
  signOut: document.getElementById("signout-btn"),
  form: document.getElementById("create-key-form"),
  name: document.querySelector('[name="name"]'),
  scopeBoxes: [...document.querySelectorAll('[name="scopes"]')],
  createStatus: document.getElementById("create-status"),
  keysSection: document.getElementById("keys-section"),
  keysBody: document.getElementById("keys-table-body"),
  keySlot: document.querySelector('[data-replace="key"]'),
  copyButtons: [...document.querySelectorAll("[data-copy]")],
};

const hint = (element, text, kind = "muted") => {
  element.textContent = text;
  element.className = `status status-${kind}`;
};

const onCopy = async (button) => {
  const code = button.parentElement.querySelector("code");
  const text = code ? code.textContent : "";
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = "Copy"), 1400);
  } catch {
    button.textContent = "Press Ctrl+C";
  }
};
els.copyButtons.forEach((button) => button.addEventListener("click", () => onCopy(button)));

const formatDate = (value) => {
  if (!value) return "never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
};

const renderKeys = (keys) => {
  els.keysSection.removeAttribute("data-hidden");
  els.keysBody.textContent = "";
  if (!keys.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="6" class="empty">No keys yet — create one above.</td>';
    els.keysBody.appendChild(row);
    return;
  }
  for (const key of keys) {
    const row = document.createElement("tr");
    const scopes = (key.scopes ?? []).map((scope) => `<code>${scope}</code>`).join(" ");
    row.innerHTML = `
      <td>${escapeHtml(key.name)}</td>
      <td><code class="key-preview">${escapeHtml(key.key_preview ?? "")}</code></td>
      <td class="scopes">${scopes}</td>
      <td>${formatDate(key.created_at)}</td>
      <td>${key.revoked_at ? `<span class="revoked">revoked</span>` : formatDate(key.last_used_at)}</td>
      <td>${key.revoked_at ? "" : `<button class="btn btn-danger btn-small" data-revoke="${escapeHtml(key.id)}">Revoke</button>`}</td>`;
    els.keysBody.appendChild(row);
  }
  els.keysBody.querySelectorAll("[data-revoke]").forEach((button) => {
    button.addEventListener("click", () => revokeKey(button, button.dataset.revoke));
  });
};

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);

const loadKeys = async () => {
  const response = await fetch("/v1/integration/keys", { headers: { accept: "application/json" } });
  if (response.status === 401) {
    window.location.assign("/auth?next=/integrations");
    return;
  }
  if (!response.ok) {
    hint(els.createStatus, "Could not load keys. Refresh and try again.", "error");
    return;
  }
  const payload = await response.json();
  renderKeys(payload.keys ?? []);
};

const revokeKey = async (button, id) => {
  button.disabled = true;
  const response = await fetch(`/v1/integration/keys/${id}`, { method: "DELETE" });
  if (response.status === 204) await loadKeys();
  else hint(els.createStatus, "Could not revoke that key.", "error");
};

els.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const scopes = els.scopeBoxes.filter((box) => box.checked).map((box) => box.value);
  if (!scopes.length) {
    hint(els.createStatus, "Select at least one scope.", "error");
    return;
  }
  els.createStatus.textContent = "";
  const response = await fetch("/v1/integration/keys", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ name: els.name.value.trim(), scopes }),
  });
  if (response.status === 401) {
    window.location.assign("/auth?next=/integrations");
    return;
  }
  if (response.status === 201) {
    const created = await response.json();
    hint(els.createStatus, `Key "${created.name}" created. Store it now — it is shown only once.`, "ok");
    if (els.keySlot) {
      els.keySlot.textContent = created.key;
      els.keySlot.parentElement?.parentElement?.closest(".code")?.classList.add("live");
    }
    els.form.reset();
    await loadKeys();
    return;
  }
  const problem = await response.json().catch(() => ({}));
  hint(els.createStatus, problem.detail ?? "Could not create the key.", "error");
});

els.signOut.addEventListener("click", async () => {
  await fetch("/v1/auth/logout", { method: "POST" });
  window.location.assign("/");
});

loadKeys();
navigator.serviceWorker?.register("/sw.js").catch(() => {});