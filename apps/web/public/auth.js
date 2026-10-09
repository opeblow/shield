const form = document.querySelector('#auth-form');
const email = document.querySelector('#email');
const password = document.querySelector('#password');
const status = document.querySelector('#auth-status');
const submit = document.querySelector('#auth-submit');
const submitLabel = document.querySelector('#auth-submit-label');
const title = document.querySelector('#auth-title');
const sub = document.querySelector('#auth-sub');
const eyebrow = document.querySelector('#auth-eyebrow');
const tabs = [...document.querySelectorAll('.auth-tab')];
const params = new URLSearchParams(location.search);
let mode = params.get('mode') === 'signin' ? 'signin' : 'signup';
const nextTarget = params.get('next');
const next = nextTarget && nextTarget.startsWith('/') ? nextTarget : null;

const copy = {
  signup: {
    eyebrow: 'Get started', title: 'Create your account',
    sub: 'Save your checks and return any time. No card required.',
    label: 'Create account', autocomplete: 'new-password'
  },
  signin: {
    eyebrow: 'Welcome back', title: 'Sign in to Shield',
    sub: 'Pick up where you left off and keep checking messages.',
    label: 'Sign in', autocomplete: 'current-password'
  }
};

function applyMode(next) {
  mode = next;
  const text = copy[mode];
  eyebrow.textContent = text.eyebrow;
  title.textContent = text.title;
  sub.textContent = text.sub;
  submitLabel.textContent = text.label;
  password.setAttribute('autocomplete', text.autocomplete);
  status.textContent = '';
  for (const tab of tabs) tab.setAttribute('aria-selected', String(tab.dataset.mode === mode));
}

for (const tab of tabs) tab.addEventListener('click', () => {
  applyMode(tab.dataset.mode === 'signin' ? 'signin' : 'signup');
  email.focus();
});

applyMode(mode);

fetch('/v1/auth/me', { cache: 'no-store' })
  .then((response) => { if (response.ok) location.replace('/app'); })
  .catch(() => {});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  status.textContent = '';
  if (!email.value.includes('@')) { email.focus(); status.textContent = 'Enter a valid email address.'; return; }
  if (mode === 'signup' && password.value.length < 8) { password.focus(); status.textContent = 'Choose a password of at least 8 characters.'; return; }
  if (password.value.length < 1) { password.focus(); status.textContent = 'Enter your password.'; return; }
  submit.disabled = true;
  const original = submitLabel.textContent;
  submitLabel.textContent = mode === 'signup' ? 'Creating account…' : 'Signing in…';
  try {
    const response = await fetch(mode === 'signup' ? '/v1/auth/register' : '/v1/auth/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: email.value, password: password.value })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 409) { applyMode('signin'); }
      throw new Error(data.detail ?? 'Sign in could not be completed.');
    }
    location.assign(next ?? '/app');
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : 'Sign in could not be completed.';
  } finally {
    submit.disabled = false;
    submitLabel.textContent = original;
  }
});
