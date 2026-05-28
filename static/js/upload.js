/**
 * upload.js — file selection, drag & drop, SHA-256, scan submission,
 * view switching, and history table.
 */

'use strict';

/* ── Constants ────────────────────────────────────────────────────────────── */
const ALLOWED_EXTENSIONS = ['.exe', '.dll', '.sys', '.scr', '.com', '.bin'];
const MAX_SIZE_BYTES      = 50 * 1024 * 1024; // 50 MB

/* ── State ────────────────────────────────────────────────────────────────── */
let selectedFile = null;

/* ── DOM refs ─────────────────────────────────────────────────────────────── */
const dropZone      = document.getElementById('drop-zone');
const fileInput     = document.getElementById('file-input');
const browseLink    = document.getElementById('browse-link');
const scanBtn       = document.getElementById('scan-btn');
const filePreview   = document.getElementById('file-preview');
const previewName   = document.getElementById('preview-name');
const previewSize   = document.getElementById('preview-size');
const previewType   = document.getElementById('preview-type');
const previewSha256 = document.getElementById('preview-sha256');
const clearBtn      = document.getElementById('clear-btn');
const uploadError   = document.getElementById('upload-error');
const loadingState  = document.getElementById('loading-state');
const loadingSub    = document.getElementById('loading-sub');
const viewUpload    = document.getElementById('view-upload');
const viewResult    = document.getElementById('view-result');
const backBtn       = document.getElementById('back-btn');
const historyTbody  = document.getElementById('history-tbody');
const footerCount   = document.getElementById('footer-scan-count');

/* ── Utilities ────────────────────────────────────────────────────────────── */

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function getExtension(filename) {
  const idx = filename.lastIndexOf('.');
  return idx === -1 ? '' : filename.slice(idx).toLowerCase();
}

function relativeTime(iso) {
  try {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60)   return Math.round(diff) + 's ago';
    if (diff < 3600) return Math.round(diff / 60) + 'm ago';
    if (diff < 86400) return Math.round(diff / 3600) + 'h ago';
    return Math.round(diff / 86400) + 'd ago';
  } catch {
    return '—';
  }
}

async function computeSHA256(file) {
  try {
    const buf  = await file.arrayBuffer();
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return 'unavailable';
  }
}

/* ── Validation ───────────────────────────────────────────────────────────── */

function validateFile(file) {
  if (!file || file.size === 0) return 'File is empty';
  const ext = getExtension(file.name);
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return 'File type "' + ext + '" not allowed. Accepted: ' + ALLOWED_EXTENSIONS.join(', ');
  }
  if (file.size > MAX_SIZE_BYTES) {
    return 'File too large (' + formatBytes(file.size) + '). Maximum: 50 MB';
  }
  return null;
}

/* ── UI State Helpers ─────────────────────────────────────────────────────── */

function showUploadError(msg) {
  uploadError.textContent = msg;
  uploadError.classList.add('visible');
}

function clearUploadError() {
  uploadError.textContent = '';
  uploadError.classList.remove('visible');
}

function showFilePreview(file, sha256) {
  previewName.textContent   = file.name;
  previewSize.textContent   = formatBytes(file.size);
  previewType.textContent   = getExtension(file.name).toUpperCase().replace('.', '');
  previewSha256.textContent = sha256 || 'computing…';
  filePreview.classList.add('visible');
  scanBtn.disabled          = false;
  scanBtn.textContent       = 'SCAN FILE';
  clearUploadError();
}

function resetUpload() {
  selectedFile              = null;
  fileInput.value           = '';
  filePreview.classList.remove('visible');
  previewSha256.textContent = 'computing…';
  scanBtn.disabled          = true;
  scanBtn.textContent       = 'SELECT A FILE TO SCAN';
  dropZone.style.display    = '';
  loadingState.classList.remove('active');
  clearUploadError();
}

function showScanning() {
  scanBtn.disabled = true;
  scanBtn.textContent = 'SCANNING…';
  loadingState.classList.add('active');
  clearUploadError();
}

function hideScanning() {
  loadingState.classList.remove('active');
}

function showScanError(msg) {
  hideScanning();
  scanBtn.disabled    = false;
  scanBtn.textContent = 'RETRY SCAN';
  showUploadError(msg || 'Scan failed. Please try again.');
}

/* ── View Switching ───────────────────────────────────────────────────────── */

function switchToResult() {
  viewUpload.classList.remove('active');
  viewResult.classList.add('active');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function switchToUpload() {
  viewResult.classList.remove('active');
  viewUpload.classList.add('active');
  resetUpload();
  loadHistory();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ── File Handling ────────────────────────────────────────────────────────── */

async function handleFileSelect(file) {
  clearUploadError();
  const err = validateFile(file);
  if (err) {
    showUploadError(err);
    selectedFile = null;
    scanBtn.disabled = true;
    scanBtn.textContent = 'SELECT A FILE TO SCAN';
    filePreview.classList.remove('visible');
    return;
  }

  selectedFile = file;

  // Show preview immediately with placeholder hash, then compute async
  showFilePreview(file, 'computing…');

  try {
    const sha256 = await computeSHA256(file);
    previewSha256.textContent = sha256;
  } catch {
    previewSha256.textContent = '(unavailable)';
  }
}

/* ── Scan Submission ──────────────────────────────────────────────────────── */

async function submitScan() {
  if (!selectedFile) return;

  showScanning();

  const phases = [
    'Running PE header analysis…',
    'Extracting sections and entropy…',
    'Scanning import table…',
    'Extracting strings…',
    'Running YARA rules…',
    'Running ML classifier…',
    'Aggregating verdict…',
  ];
  let phaseIdx = 0;
  const phaseTimer = setInterval(() => {
    if (phaseIdx < phases.length) {
      loadingSub.textContent = phases[phaseIdx++];
    }
  }, 1200);

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const res  = await fetch('/api/scan', { method: 'POST', body: formData });
    const data = await res.json();

    clearInterval(phaseTimer);

    if (!res.ok) {
      showScanError(data.error || 'Server returned ' + res.status);
      return;
    }

    // Render the report
    renderReport(data);
    switchToResult();
    loadHistory();

  } catch (err) {
    clearInterval(phaseTimer);
    showScanError(err.message || 'Network error — is the server running?');
  }
}

/* ── History Table ────────────────────────────────────────────────────────── */

async function loadHistory() {
  try {
    const res  = await fetch('/api/history?limit=10');
    const data = await res.json();
    renderHistory(data.scans || []);
    if (footerCount) footerCount.textContent = (data.total || 0) + ' scan' + (data.total === 1 ? '' : 's');
  } catch {
    // Non-fatal — history failing doesn't break the app
  }
}

function verdictBadge(verdict) {
  const v = (verdict || 'pending').toLowerCase();
  return '<span class="verdict-badge ' + v + '">' + v.toUpperCase() + '</span>';
}

function renderHistory(scans) {
  if (!scans || scans.length === 0) {
    historyTbody.innerHTML = '<tr><td colspan="6" class="empty-history">No scans yet — drop a file above to get started</td></tr>';
    return;
  }

  historyTbody.innerHTML = '';
  scans.forEach(scan => {
    const tr = document.createElement('tr');
    tr.setAttribute('role', 'button');
    tr.setAttribute('tabindex', '0');
    tr.setAttribute('title', 'Load report for ' + (scan.filename || '?'));
    tr.setAttribute('data-id', scan.id);

    const conf = scan.confidence != null ? (scan.confidence * 100).toFixed(0) + '%' : '—';

    tr.innerHTML =
      '<td class="filename">' + escHtmlTable(scan.filename || '—') + '</td>' +
      '<td>' + formatBytes(scan.file_size) + '</td>' +
      '<td>' + verdictBadge(scan.verdict) + '</td>' +
      '<td>' + conf + '</td>' +
      '<td>' + relativeTime(scan.created_at) + '</td>' +
      '<td style="text-align:right">' +
        '<button class="api-chip normal" data-delete="' + scan.id + '" style="cursor:pointer;padding:3px 10px" title="Delete this scan" aria-label="Delete scan">✕</button>' +
      '</td>';

    // Click row → load report
    tr.addEventListener('click', async (e) => {
      if (e.target.hasAttribute('data-delete')) return; // handled below
      await loadReport(scan.id);
    });

    tr.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter' && !e.target.hasAttribute('data-delete')) await loadReport(scan.id);
    });

    historyTbody.appendChild(tr);
  });

  // Delete buttons
  historyTbody.querySelectorAll('[data-delete]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.getAttribute('data-delete');
      if (!id) return;
      try {
        await fetch('/api/scan/' + id, { method: 'DELETE' });
        loadHistory();
      } catch {
        // silent
      }
    });
  });
}

async function loadReport(scanId) {
  try {
    const res  = await fetch('/api/report/' + scanId);
    const data = await res.json();
    if (!res.ok) { alert(data.error || 'Could not load report'); return; }
    renderReport(data);
    switchToResult();
  } catch (err) {
    alert('Failed to load report: ' + err.message);
  }
}

function escHtmlTable(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ── Server Status ────────────────────────────────────────────────────────── */

async function checkStatus() {
  const dot  = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  try {
    const res  = await fetch('/api/status');
    const data = await res.json();

    if (data.status === 'ok') {
      const parts = [];
      if (data.model_loaded) parts.push('ML');
      if (data.yara_available) parts.push('YARA');
      if (data.pefile_available) parts.push('PE');

      dot.style.background  = 'var(--clean)';
      dot.style.boxShadow   = '0 0 6px var(--clean)';
      text.textContent      = parts.length ? parts.join(' · ') + ' active' : 'online (static only)';
    }
  } catch {
    dot.style.background = 'var(--malware)';
    dot.style.boxShadow  = '0 0 6px var(--malware)';
    text.textContent     = 'server offline';
  }
}

/* ── Event Wiring ─────────────────────────────────────────────────────────── */

// Drop zone: dragover
dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', e => {
  if (!dropZone.contains(e.relatedTarget)) {
    dropZone.classList.remove('drag-over');
  }
});

dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) handleFileSelect(file);
});

// Drop zone: keyboard
dropZone.addEventListener('keydown', e => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
});

// Click zone
dropZone.addEventListener('click', () => fileInput.click());

// Browse link (child of drop zone — prevent double trigger via stopPropagation)
browseLink.addEventListener('click', e => {
  e.stopPropagation();
  fileInput.click();
});

// File input change
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) handleFileSelect(fileInput.files[0]);
});

// Clear button
clearBtn.addEventListener('click', e => {
  e.stopPropagation();
  resetUpload();
});

// Scan button
scanBtn.addEventListener('click', submitScan);

// Back button
backBtn.addEventListener('click', switchToUpload);

/* ── Initialise ───────────────────────────────────────────────────────────── */

checkStatus();
setInterval(checkStatus, 30000); // re-check every 30s
loadHistory();
