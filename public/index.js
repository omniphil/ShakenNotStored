const messageEl = document.getElementById('message');
const charCountEl = document.getElementById('charCount');
const createBtn = document.getElementById('createBtn');
const copyBtn = document.getElementById('copyBtn');
const resetBtn = document.getElementById('resetBtn');
const resultEl = document.getElementById('result');
const inputCardEl = document.getElementById('inputCard');
const featuresEl = document.querySelector('.features');
const secretUrlEl = document.getElementById('secretUrl');
const dropZone = document.getElementById('dropZone');
const dropPrompt = document.getElementById('dropPrompt');
const filePreview = document.getElementById('filePreview');
const fileInput = document.getElementById('fileInput');
const fileNameEl = document.getElementById('fileName');
const fileSizeEl = document.getElementById('fileSizeDisplay');
const removeFileBtn = document.getElementById('removeFile');
const fileErrorEl = document.getElementById('fileError');

const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB

let selectedFile = null;

messageEl.addEventListener('input', () => {
  charCountEl.textContent = messageEl.value.length;
});

createBtn.addEventListener('click', createSecret);
copyBtn.addEventListener('click', copyUrl);
resetBtn.addEventListener('click', resetForm);

// Drop zone events
dropZone.addEventListener('click', (e) => {
  if (e.target === removeFileBtn || e.target.closest('.remove-file')) return;
  if (e.target.classList.contains('file-browse')) return;
  fileInput.click();
});

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (e.dataTransfer.files.length) {
    handleFile(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener('change', () => {
  if (fileInput.files.length) {
    handleFile(fileInput.files[0]);
  }
});

removeFileBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  clearFile();
});

function handleFile(file) {
  fileErrorEl.textContent = '';
  if (file.size > MAX_FILE_SIZE) {
    fileErrorEl.textContent = `File is too large (${formatSize(file.size)}). Maximum is 25 MB.`;
    return;
  }
  if (file.size === 0) {
    fileErrorEl.textContent = 'File is empty.';
    return;
  }
  selectedFile = file;
  fileNameEl.textContent = file.name;
  fileSizeEl.textContent = formatSize(file.size);
  dropPrompt.classList.add('hidden');
  filePreview.classList.add('visible');
}

function clearFile() {
  selectedFile = null;
  fileInput.value = '';
  fileErrorEl.textContent = '';
  filePreview.classList.remove('visible');
  dropPrompt.classList.remove('hidden');
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function uint8ToBase64(bytes) {
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

async function encryptMessage(plaintext) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  const encryptedB64 = uint8ToBase64(combined);
  const keyB64 = uint8ToBase64(new Uint8Array(rawKey));
  return { encrypted: encryptedB64, key: keyB64 };
}

async function createSecret() {
  const message = messageEl.value.trim();
  if (!message && !selectedFile) return;

  createBtn.disabled = true;

  try {
    // Build envelope
    const envelope = { version: 1 };
    if (message) envelope.text = message;

    if (selectedFile) {
      createBtn.textContent = 'Reading file...';
      const buffer = await readFileAsArrayBuffer(selectedFile);
      const fileBase64 = uint8ToBase64(new Uint8Array(buffer));
      envelope.file = {
        name: selectedFile.name,
        type: selectedFile.type || 'application/octet-stream',
        data: fileBase64
      };
    }

    createBtn.textContent = 'Encrypting...';
    const envelopeJson = JSON.stringify(envelope);
    const { encrypted, key } = await encryptMessage(envelopeJson);

    createBtn.textContent = 'Uploading...';
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
    inputCardEl.classList.add('hidden');
    featuresEl.classList.add('hidden');
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
  inputCardEl.classList.remove('hidden');
  featuresEl.classList.remove('hidden');
  clearFile();
}
