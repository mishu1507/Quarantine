/**
 * report.js — renders a completed scan/report object into the result view.
 * All functions are pure DOM manipulators — no fetch calls here.
 */

'use strict';

/* ── Helpers ──────────────────────────────────────────────────────────────── */

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return '—';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

function escHtml(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ── Verdict Banner ───────────────────────────────────────────────────────── */

function renderVerdict(verdict, confidence) {
  const banner = document.getElementById('verdict-banner');
  const word   = document.getElementById('verdict-word');
  const conf   = document.getElementById('verdict-confidence');

  verdict = (verdict || 'unknown').toLowerCase();
  banner.className = 'verdict-banner ' + verdict;
  word.textContent = verdict.toUpperCase();

  const pct = (typeof confidence === 'number') ? (confidence * 100).toFixed(1) + '% confidence' : '—';
  conf.textContent = pct;

  document.getElementById('score-bar-track').setAttribute('aria-valuenow', Math.round((confidence || 0) * 100));
}

/* ── File Info Card ───────────────────────────────────────────────────────── */

function renderFileInfo(scan) {
  document.getElementById('info-filename').textContent = scan.filename || '—';
  document.getElementById('info-size').textContent     = formatBytes(scan.file_size);
  document.getElementById('info-md5').textContent      = scan.md5  || '—';
  document.getElementById('info-sha256').textContent   = scan.sha256 || '—';
}

/* ── ML Score Bar ─────────────────────────────────────────────────────────── */

function renderScoreBar(confidence, verdict) {
  const fill = document.getElementById('score-bar-fill');
  const val  = document.getElementById('score-value');

  const pct = Math.round((confidence || 0) * 100);
  verdict = (verdict || 'clean').toLowerCase();

  // Animate after short delay to allow the transition to fire
  requestAnimationFrame(() => {
    setTimeout(() => {
      fill.style.width = pct + '%';
      fill.className = 'score-bar-fill ' + verdict;
    }, 80);
  });

  if (confidence === null || confidence === undefined) {
    val.textContent = 'N/A (no model)';
    val.style.color = 'var(--text-muted)';
  } else {
    val.textContent = pct + '%';
    val.style.color = verdict === 'clean' ? 'var(--clean)'
                    : verdict === 'malware' ? 'var(--malware)'
                    : 'var(--suspicious)';
  }
}

/* ── Packing Card ─────────────────────────────────────────────────────────── */

function renderPacking(isPacked, packerName) {
  const badge = document.getElementById('packing-badge');
  const name  = document.getElementById('packer-name');

  if (isPacked) {
    badge.textContent  = 'PACKED';
    badge.className    = 'packing-badge packed';
    name.textContent   = packerName ? '— ' + packerName : '';
  } else {
    badge.textContent  = 'NOT PACKED';
    badge.className    = 'packing-badge clean';
    name.textContent   = '';
  }
}

/* ── Indicators List ──────────────────────────────────────────────────────── */

function renderIndicators(indicators) {
  const list = document.getElementById('indicators-list');
  list.innerHTML = '';

  if (!indicators || indicators.length === 0) {
    list.innerHTML = '<div class="indicator-item"><span class="severity-dot info"></span><span class="indicator-text">No indicators detected</span></div>';
    return;
  }

  // Sort: high → medium → low → info
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const sorted = [...indicators].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

  sorted.forEach(ind => {
    const sev  = (ind.severity || 'info').toLowerCase();
    const item = document.createElement('div');
    item.className = 'indicator-item';
    item.innerHTML =
      '<span class="severity-dot ' + escHtml(sev) + '" title="' + escHtml(sev) + '"></span>' +
      '<span class="indicator-text">' + escHtml(ind.text || '') + '</span>';
    list.appendChild(item);
  });
}

/* ── YARA Matches ─────────────────────────────────────────────────────────── */

function renderYara(matches) {
  const container = document.getElementById('yara-list');
  container.innerHTML = '';

  if (!matches || matches.length === 0) {
    const badge = document.createElement('span');
    badge.className   = 'yara-badge clean';
    badge.textContent = '✓ No matches';
    container.appendChild(badge);
    return;
  }

  matches.forEach(rule => {
    const badge = document.createElement('span');
    badge.className   = 'yara-badge match';
    badge.textContent = rule;
    badge.title       = 'YARA rule: ' + rule;
    container.appendChild(badge);
  });
}

/* ── PE Sections Table ────────────────────────────────────────────────────── */

function renderSections(sections) {
  const tbody = document.getElementById('sections-tbody');
  tbody.innerHTML = '';

  if (!sections || sections.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-history">No section data available</td></tr>';
    return;
  }

  sections.forEach(sec => {
    const ent   = parseFloat(sec.entropy) || 0;
    const pct   = ((ent / 8) * 100).toFixed(1);
    const cls   = ent > 7.0 ? 'high' : ent > 6.0 ? 'medium' : '';
    const known = sec.is_known;

    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td><code style="font-family:var(--font-mono);font-size:0.78rem;color:var(--text-code)">' + escHtml(sec.name || '?') + '</code></td>' +
      '<td>' + formatBytes(sec.raw_size) + '</td>' +
      '<td>' +
        '<div class="entropy-cell">' +
          '<div class="entropy-mini-bar"><div class="entropy-mini-fill ' + cls + '" style="width:' + pct + '%"></div></div>' +
          '<span class="entropy-num">' + ent.toFixed(2) + '</span>' +
        '</div>' +
      '</td>' +
      '<td><span class="known-badge ' + (known ? 'known' : 'unknown') + '">' + (known ? 'known' : 'unknown') + '</span></td>';
    tbody.appendChild(tr);
  });
}

/* ── Import Table ─────────────────────────────────────────────────────────── */

function renderImports(imports) {
  const stats   = document.getElementById('import-stats');
  const apiList = document.getElementById('suspicious-api-list');
  stats.innerHTML   = '';
  apiList.innerHTML = '';

  if (!imports) return;

  // Stats row
  const items = [
    { num: imports.total_count ?? 0,  label: 'Total Imports' },
    { num: imports.dll_count ?? 0,    label: 'DLLs' },
    { num: (imports.suspicious_apis || []).length, label: 'Suspicious APIs' },
  ];
  items.forEach(it => {
    const div = document.createElement('div');
    div.className = 'import-stat';
    div.innerHTML =
      '<span class="import-stat-num">' + it.num + '</span>' +
      '<span class="import-stat-label">' + it.label + '</span>';
    stats.appendChild(div);
  });

  // Suspicious APIs
  const suspicious = imports.suspicious_apis || [];
  const allDlls    = imports.all_dlls || [];

  if (suspicious.length > 0) {
    const label = document.createElement('div');
    label.style.cssText = 'width:100%;font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;margin-top:8px;';
    label.textContent = 'Suspicious API calls';
    apiList.appendChild(label);

    suspicious.forEach(api => {
      const chip = document.createElement('span');
      chip.className   = 'api-chip suspicious';
      chip.textContent = api;
      apiList.appendChild(chip);
    });
  }

  if (allDlls.length > 0) {
    const label = document.createElement('div');
    label.style.cssText = 'width:100%;font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;margin-top:12px;';
    label.textContent = 'Imported DLLs';
    apiList.appendChild(label);

    allDlls.forEach(dll => {
      const chip = document.createElement('span');
      chip.className   = 'api-chip normal';
      chip.textContent = dll;
      apiList.appendChild(chip);
    });
  }

  if (suspicious.length === 0 && allDlls.length === 0) {
    apiList.innerHTML = '<span style="font-size:0.78rem;color:var(--text-muted);font-family:var(--font-mono)">No import data available</span>';
  }
}

/* ── Strings: Collapsible Sections ───────────────────────────────────────── */

function makeCollapsible(title, items, emptyMsg) {
  const wrap = document.createElement('div');
  wrap.className = 'collapsible';

  const header = document.createElement('div');
  header.className = 'collapsible-header';
  header.setAttribute('role', 'button');
  header.setAttribute('tabindex', '0');
  header.setAttribute('aria-expanded', 'false');
  header.innerHTML =
    '<span class="collapsible-title">' +
      escHtml(title) +
      '<span class="collapsible-count">' + (items ? items.length : 0) + '</span>' +
    '</span>' +
    '<span class="collapsible-arrow">▼</span>';

  const body = document.createElement('div');
  body.className = 'collapsible-body';

  if (!items || items.length === 0) {
    body.innerHTML = '<div class="strings-empty">' + escHtml(emptyMsg || 'None found') + '</div>';
  } else {
    items.forEach(s => {
      const item = document.createElement('div');
      item.className   = 'string-item';
      item.textContent = s;
      body.appendChild(item);
    });
  }

  const toggle = () => {
    const open = wrap.classList.toggle('open');
    header.setAttribute('aria-expanded', open);
  };

  header.addEventListener('click', toggle);
  header.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });

  wrap.appendChild(header);
  wrap.appendChild(body);
  return wrap;
}

function renderStrings(strings) {
  const container = document.getElementById('strings-collapsibles');
  container.innerHTML = '';

  if (!strings) {
    container.innerHTML = '<div class="strings-empty">No string data</div>';
    return;
  }

  container.appendChild(makeCollapsible('URLs (' + (strings.urls || []).length + ')', strings.urls, 'No URLs found'));
  container.appendChild(makeCollapsible('IP Addresses', strings.ips, 'No IPs found'));
  container.appendChild(makeCollapsible('Registry Keys', strings.registry_keys, 'No registry keys found'));
  container.appendChild(makeCollapsible('Suspicious Strings', strings.suspicious, 'No suspicious strings found'));
}

/* ── Master render ────────────────────────────────────────────────────────── */

function renderReport(data) {
  const { scan, report } = data;

  renderVerdict(report.verdict, report.confidence);
  renderFileInfo(scan);
  renderScoreBar(report.ml_score, report.verdict);
  renderPacking(report.is_packed, report.packer_name);
  renderIndicators(report.indicators);
  renderYara(report.yara_matches);

  const peInfo = report.pe_info || {};
  renderSections(peInfo.sections || []);
  renderImports(peInfo.imports || {});

  const staticFeat = report.static_features || {};
  renderStrings(staticFeat.strings || {});
}
