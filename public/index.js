const messageEl = document.getElementById('message');
const charCountEl = document.getElementById('charCount');
const createBtn = document.getElementById('createBtn');
const copyBtn = document.getElementById('copyBtn');
const resetBtn = document.getElementById('resetBtn');
const resultEl = document.getElementById('result');
const inputCardEl = document.getElementById('inputCard');
const featuresEl = document.querySelector('.features');
const secretUrlEl = document.getElementById('secretUrl');

messageEl.addEventListener('input', () => {
  charCountEl.textContent = messageEl.value.length;
});

createBtn.addEventListener('click', createSecret);
copyBtn.addEventListener('click', copyUrl);
resetBtn.addEventListener('click', resetForm);

async function encryptMessage(plaintext) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  const encryptedB64 = btoa(String.fromCharCode(...combined));
  const keyB64 = btoa(String.fromCharCode(...new Uint8Array(rawKey)));
  return { encrypted: encryptedB64, key: keyB64 };
}

async function createSecret() {
  const message = messageEl.value.trim();
  if (!message) {
    return;
  }

  createBtn.disabled = true;
  createBtn.textContent = 'Encrypting...';

  try {
    const { encrypted, key } = await encryptMessage(message);
    const res = await fetch('/api/secrets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      body: JSON.stringify({ message: encrypted })
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      alert(data.error || 'Something went wrong');
      return;
    }

    secretUrlEl.value = `${window.location.origin}${data.url}#${key}`;
    resultEl.classList.add('visible');
    inputCardEl.style.display = 'none';
    featuresEl.style.display = 'none';
  } catch {
    alert('Failed to create secret. Please try again.');
  } finally {
    createBtn.disabled = false;
    createBtn.textContent = 'Create Secret Link';
  }
}

async function copyUrl() {
  try {
    await navigator.clipboard.writeText(secretUrlEl.value);
    copyBtn.textContent = 'Copied!';
    setTimeout(() => {
      copyBtn.textContent = 'Copy';
    }, 2000);
  } catch {
    alert('Unable to copy the link automatically.');
  }
}

function resetForm() {
  messageEl.value = '';
  charCountEl.textContent = '0';
  secretUrlEl.value = '';
  resultEl.classList.remove('visible');
  inputCardEl.style.display = 'block';
  featuresEl.style.display = 'grid';
}
