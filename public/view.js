const loadingEl = document.getElementById('loading');
const notFoundEl = document.getElementById('not-found');
const secretDisplayEl = document.getElementById('secret-display');
const messageContentEl = document.getElementById('message-content');
const secretId = window.location.pathname.split('/s/')[1];
const encryptionKey = window.location.hash.slice(1);

void loadSecret();

async function loadSecret() {
  try {
    const res = await fetch(`/api/secrets/${secretId}`, { cache: 'no-store' });
    loadingEl.style.display = 'none';

    if (!res.ok) {
      notFoundEl.style.display = 'block';
      return;
    }

    const data = await res.json();
    try {
      const plaintext = encryptionKey
        ? await decryptMessage(data.message, encryptionKey)
        : data.message;
      messageContentEl.textContent = plaintext;
    } catch {
      messageContentEl.textContent = '[Unable to decrypt - invalid or missing key]';
    }

    secretDisplayEl.style.display = 'block';
  } catch {
    loadingEl.style.display = 'none';
    notFoundEl.style.display = 'block';
  }
}

async function decryptMessage(encryptedB64, keyB64) {
  const combined = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
  const keyBytes = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}
