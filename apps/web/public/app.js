import { decodeQrFile } from './qr.js';

const me = await fetch('/v1/auth/me', { cache: 'no-store' })
  .then((response) => response.ok ? response.json() : null)
  .catch(() => null);
if (!me?.user) {
  location.replace('/auth');
} else {
  const emailLabel = document.querySelector('#user-email');
  if (emailLabel) emailLabel.textContent = me.user.email;
  document.querySelector('#signout')?.addEventListener('click', async () => {
    try { await fetch('/v1/auth/logout', { method: 'POST' }); } catch { /* sign out locally regardless */ }
    location.assign('/');
  });
}

const message = document.querySelector('#message');
const count = document.querySelector('#char-count');
const language = document.querySelector('#language');
const button = document.querySelector('#scan');
const result = document.querySelector('#result');
const year = document.querySelector('#year');
const qrFile = document.querySelector('#qr-file');
const chooseQr = document.querySelector('#choose-qr');
const qrStatus = document.querySelector('#qr-status');
const reportSection = document.querySelector('#community-report');
const reportForm = document.querySelector('#report-form');
const reportStatus = document.querySelector('#report-status');
const reportSubmit = document.querySelector('#report-submit');
let communityReportAvailable = false;
year.textContent = String(new Date().getFullYear());

fetch('/readyz', { cache: 'no-store' }).then((response) => response.ok ? response.json() : null)
  .then((health) => { communityReportAvailable = health?.community_reports === true; })
  .catch(() => { communityReportAvailable = false; });

if (!globalThis.BarcodeDetector || !globalThis.createImageBitmap) {
  chooseQr.disabled = true;
  qrStatus.textContent = 'QR image reading is not available in this browser. Paste the link or message instead.';
}
chooseQr.addEventListener('click', () => qrFile.click());
qrFile.addEventListener('change', async () => {
  const file = qrFile.files?.[0];
  if (!file) return;
  chooseQr.disabled = true;
  qrStatus.textContent = 'Reading the image on this device…';
  try {
    message.value = await decodeQrFile(file);
    message.dispatchEvent(new Event('input', { bubbles: true }));
    message.focus();
    qrStatus.textContent = 'QR content loaded. Review it, then choose “Check this message” to submit the text.';
  } catch (error) {
    qrStatus.textContent = error instanceof Error ? error.message : 'The QR image could not be read.';
  } finally {
    qrFile.value = '';
    chooseQr.disabled = !globalThis.BarcodeDetector || !globalThis.createImageBitmap;
  }
});

message.addEventListener('input', () => { count.textContent = `${message.value.length.toLocaleString()} / 20,000`; });

function verdictLabel(verdict) {
  return ({ safe: 'No scam signs found', caution: 'Pause and check', likely_scam: 'Likely scam', scam: 'Strong scam signs' })[verdict] ?? 'Scan result';
}

button.addEventListener('click', async () => {
  if (message.value.trim().length < 2) {
    message.focus();
    message.setCustomValidity('Paste at least two characters to check.');
    message.reportValidity();
    return;
  }
  message.setCustomValidity('');
  button.disabled = true;
  button.querySelector('span:first-child').textContent = 'Checking…';
  result.hidden = true;
  try {
    const response = await fetch('/v1/scans', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: message.value, language: language.value })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? 'The scan could not be completed. Try again.');
    result.dataset.verdict = data.verdict;
    result.replaceChildren();
    const heading = document.createElement('h3');
    heading.textContent = verdictLabel(data.verdict);
    const messageText = document.createElement('p');
    messageText.textContent = data.customer_message.text;
    const confidence = document.createElement('p');
    confidence.className = 'score';
    confidence.textContent = `${data.model_version === 'rules-v1' ? 'Rule-based estimate (not statistically calibrated)' : 'AI assessment'} · ${Math.round(data.confidence * 100)}% confidence`;
    result.append(heading, messageText, confidence);
    const helpLink = document.createElement('a');
    helpLink.href = '/recovery.html';
    helpLink.textContent = 'If money has already moved, see immediate steps.';
    result.append(helpLink);
    if (!data.language_reviewed) {
      const review = document.createElement('p');
      review.className = 'score';
      review.textContent = 'This language wording has not yet been reviewed by native speakers.';
      result.append(review);
    }
    if (data.reasons.length) {
      const list = document.createElement('ul');
      for (const reason of data.reasons) {
        const item = document.createElement('li');
        item.textContent = reason.text;
        list.append(item);
      }
      result.append(list);
    }
    result.hidden = false;
    reportSection.hidden = !communityReportAvailable;
  } catch (error) {
    result.dataset.verdict = 'error';
    const text = document.createElement('p');
    text.className = 'error';
    text.textContent = error instanceof Error ? error.message : 'The scan could not be completed. Try again.';
    result.replaceChildren(text);
    result.hidden = false;
    reportSection.hidden = true;
  } finally {
    button.disabled = false;
    button.querySelector('span:first-child').textContent = 'Check this message';
  }
});

reportForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!document.querySelector('#report-consent').checked) return;
  reportSubmit.disabled = true;
  reportStatus.textContent = 'Sending your report securely…';
  try {
    const response = await fetch('/v1/reports', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: document.querySelector('#report-type').value,
        value: document.querySelector('#report-value').value,
        scamType: document.querySelector('#report-category').value,
        evidence: document.querySelector('#report-evidence').value
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? 'The report could not be submitted.');
    reportStatus.textContent = 'Report received for review. It will not affect shared reputation unless a moderator verifies it.';
    reportForm.reset();
  } catch (error) {
    reportStatus.textContent = error instanceof Error ? error.message : 'The report could not be submitted.';
  } finally {
    reportSubmit.disabled = false;
  }
});

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
