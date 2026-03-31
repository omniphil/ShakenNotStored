const revealPromptEl = document.getElementById('reveal-prompt');
const revealBtn = document.getElementById('revealBtn');
const loadingEl = document.getElementById('loading');
const notFoundEl = document.getElementById('not-found');
const secretDisplayEl = document.getElementById('secret-display');
const messageContentEl = document.getElementById('message-content');
const textSection = document.getElementById('text-section');
const fileSection = document.getElementById('file-section');
const dlFileName = document.getElementById('dl-file-name');
const dlFileSize = document.getElementById('dl-file-size');
const downloadBtn = document.getElementById('downloadBtn');
const secretId = window.location.pathname.split('/s/')[1];
const encryptionKey = window.location.hash.slice(1);

let pendingFileData = null;

revealBtn.addEventListener('click', () => {
  revealPromptEl.style.display = 'none';
  loadingEl.style.display = 'block';
  loadSecret();
});

downloadBtn.addEventListener('click', () => {
  if (pendingFileData) downloadFile(pendingFileData);
});

function base64ToUint8(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function downloadFile(fileData) {
  const bytes = base64ToUint8(fileData.data);
  const blob = new Blob([bytes], { type: fileData.type || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileData.name || 'download';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function loadSecret() {
  try {
    const res = await fetch(`/api/secrets/${secretId}`, { cache: 'no-store' });
    loadingEl.style.display = 'none';

    if (!res.ok) {
      notFoundEl.style.display = 'block';
      return;
    }

    const data = await res.json();
    let plaintext;
    try {
      plaintext = encryptionKey
        ? await decryptMessage(data.message, encryptionKey)
        : data.message;
    } catch {
      messageContentEl.textContent = '[Unable to decrypt - invalid or missing key]';
      secretDisplayEl.style.display = 'block';
      return;
    }

    // Parse envelope or fall back to legacy plain text
    let envelope;
    try {
      envelope = JSON.parse(plaintext);
      if (!envelope.version) throw new Error('not an envelope');
    } catch {
      envelope = { version: 0, text: plaintext };
    }

    // Display text
    if (envelope.text) {
      messageContentEl.textContent = envelope.text;
      textSection.style.display = 'block';
    } else {
      textSection.style.display = 'none';
    }

    // Display file
    if (envelope.file) {
      pendingFileData = envelope.file;
      dlFileName.textContent = envelope.file.name || 'file';
      const approxSize = Math.round(envelope.file.data.length * 3 / 4);
      dlFileSize.textContent = formatSize(approxSize);
      fileSection.style.display = 'block';
    }

    secretDisplayEl.style.display = 'block';
  } catch {
    loadingEl.style.display = 'none';
    notFoundEl.style.display = 'block';
  }
}

async function decryptMessage(encryptedB64, keyB64) {
  const combined = base64ToUint8(encryptedB64);
  const keyBytes = base64ToUint8(keyB64);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}
