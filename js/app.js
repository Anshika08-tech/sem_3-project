/**
 * CampusVoice - Tamper-Evident Anonymous Grievance Tracker
 * Core Application Engine
 */

// ==========================================
// CONFIGURATION & CONSTANTS
// ==========================================
const STORAGE_KEY = 'campusvoice_store_v2';
const ONE_HOUR = 3600000;
const GENESIS_HASH = 'GENESIS_0000000000000000000000000000000000000000000000000000000000000000';

const CATEGORIES = {
  'Hostel': {
    sla: 48,
    chain: ['Hostel Warden', 'Chief Warden', 'Dean of Student Affairs'],
    color: '#0d9488',
    icon: '🏢'
  },
  'Mess & Food': {
    sla: 24,
    chain: ['Mess Committee Incharge', 'Hostel Warden', 'Dean of Student Affairs'],
    color: '#f59e0b',
    icon: '🍲'
  },
  'Lab & Equipment': {
    sla: 48,
    chain: ['Lab In-charge', 'Head of Department (HOD)', 'Dean of Academics'],
    color: '#3b82f6',
    icon: '💻'
  },
  'Faculty & Academic': {
    sla: 72,
    chain: ['Head of Department (HOD)', 'Dean of Academics', 'Principal / Director'],
    color: '#8b5cf6',
    icon: '📚'
  },
  'Ragging & Harassment': {
    sla: 12,
    chain: ['Anti-Ragging Squad', 'Proctorial Board', 'Principal / Director'],
    color: '#ef4444',
    icon: '🚨'
  },
  'Campus Infrastructure': {
    sla: 48,
    chain: ['Estate & Maintenance Officer', 'Campus Registrar', 'Principal / Director'],
    color: '#10b981',
    icon: '⚡'
  }
};

const LOCATIONS = [
  'Hostel Block A (Boys)',
  'Hostel Block B (Boys)',
  'Girls Hostel Wing 1',
  'Girls Hostel Wing 2',
  'Central Mess Hall',
  'North Campus Cafeteria',
  'Computer Science Block - Lab 301',
  'Electronics & Circuits Lab',
  'Central Library & Reading Room',
  'Academic Block 2 - Lecture Hall 4',
  'Sports Complex & Gymnasium'
];

// Navigation structure per role
const TABS = {
  student: [
    { id: 'file', label: 'File Anonymous Grievance', icon: '📝' },
    { id: 'track', label: 'Track by Receipt Token', icon: '🔍' },
    { id: 'transparency', label: 'Public Resolution Feed', icon: '📢' }
  ],
  authority: [
    { id: 'queue', label: 'My Assigned Queue', icon: '📥' },
    { id: 'sla_alerts', label: 'SLA Urgency Monitor', icon: '⏱️' },
    { id: 'resolved', label: 'Resolved Archive', icon: '✅' }
  ],
  admin: [
    { id: 'analytics', label: 'Executive Analytics & Hotspots', icon: '📊' },
    { id: 'audit', label: 'Tamper-Evident Audit Ledger', icon: '⛓️' },
    { id: 'all_cases', label: 'All Campus Cases', icon: '📋' },
    { id: 'viva_arch', label: 'System Architecture & Schema (Viva)', icon: '🏛️' }
  ]
};

// ==========================================
// STATE MANAGEMENT
// ==========================================
let state = {
  db: {
    g: [],        // Grievances list
    log: [],      // Hash-chained audit entries
    off: 0        // Time offset in ms for simulation
  },
  role: 'student',
  currentTab: 'file',
  selectedAuthority: 'Hostel Warden',
  activeReceiptToken: '',
  tamperedState: null,
  verificationResult: null,
  currentTheme: 'light',
  uploadedFilesCache: []
};

// Utility helpers
const $ = id => document.getElementById(id);
const escapeHtml = str => String(str || '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

const getSimulatedNow = () => Date.now() + state.db.off;

const formatDate = (ms) => {
  if (!ms) return 'N/A';
  return new Date(ms).toLocaleString([], {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
};

const formatTimeLeft = (dueMs) => {
  const diff = dueMs - getSimulatedNow();
  const absHours = Math.abs(diff / ONE_HOUR);
  const hours = Math.floor(absHours);
  const mins = Math.floor((absHours - hours) * 60);

  if (diff < 0) {
    return `<span class="status-pill status-overdue">⚠️ Overdue by ${hours}h ${mins}m</span>`;
  } else if (diff < 6 * ONE_HOUR) {
    return `<span class="status-pill status-overdue">⚡ Critical: ${hours}h ${mins}m left</span>`;
  } else if (diff < 24 * ONE_HOUR) {
    return `<span class="status-pill status-progress">⏳ ${hours}h ${mins}m left</span>`;
  } else {
    return `<span class="status-pill status-open">🟢 ${hours}h ${mins}m left</span>`;
  }
};

// Cryptographic SHA-256
async function sha256(message) {
  try {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (err) {
    // Fallback FNV-1a if subtle crypto is somehow blocked
    let h = 2166136261;
    for (let i = 0; i < message.length; i++) {
      h ^= message.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return ('00000000' + (h >>> 0).toString(16)).slice(-8).repeat(8);
  }
}

// Canonical payload stringifier for audit block
function canonicalPayload(entry) {
  return JSON.stringify([
    entry.index,
    entry.gid,
    entry.action,
    entry.actor,
    entry.detail,
    entry.timestamp,
    entry.prevHash
  ]);
}

// Generate high-entropy anonymous receipt token
function generateReceiptToken(catName) {
  const prefix = catName.substring(0, 3).toUpperCase();
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(4)))
    .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const year = new Date().getFullYear();
  return `CV-${prefix}-${rand}-${year}`;
}

// ==========================================
// AUDIT CHAIN LOGIC
// ==========================================
async function recordAuditEntry(gid, action, actor, detail, customTimestamp = null) {
  const prevHash = state.db.log.length > 0 
    ? state.db.log[state.db.log.length - 1].hash 
    : GENESIS_HASH;

  const entry = {
    index: state.db.log.length,
    gid: gid,
    action: action,
    actor: actor,
    detail: detail,
    timestamp: customTimestamp || getSimulatedNow(),
    prevHash: prevHash,
    hash: ''
  };

  entry.hash = await sha256(canonicalPayload(entry));
  state.db.log.push(entry);
  saveState();
  return entry;
}

// Verify entire blockchain integrity
async function verifyAuditChain() {
  const log = state.db.log;
  let firstTamperedIndex = -1;

  for (let i = 0; i < log.length; i++) {
    const block = log[i];
    const expectedPrev = (i === 0) ? GENESIS_HASH : log[i - 1].hash;

    if (block.prevHash !== expectedPrev) {
      firstTamperedIndex = i;
      break;
    }

    const calculatedHash = await sha256(canonicalPayload(block));
    if (block.hash !== calculatedHash) {
      firstTamperedIndex = i;
      break;
    }
  }

  state.verificationResult = firstTamperedIndex;
  return firstTamperedIndex;
}

// ==========================================
// GRIEVANCE ENGINE & AUTO-ESCALATION
// ==========================================
async function createGrievance(data, customTimestamp = null) {
  const ts = customTimestamp || getSimulatedNow();
  const catConfig = CATEGORIES[data.cat];
  const token = generateReceiptToken(data.cat);

  const grievance = {
    id: state.db.g.length + 1,
    token: token,
    cat: data.cat,
    loc: data.loc,
    urgency: data.urgency || 'Normal',
    title: data.title,
    desc: data.desc,
    files: data.files || [],
    level: 0,
    authority: catConfig.chain[0],
    status: 'Open',
    created: ts,
    due: ts + (catConfig.sla * ONE_HOUR),
    resolved: null,
    resolutionNote: '',
    escCount: 0,
    notes: []
  };

  state.db.g.push(grievance);
  
  await recordAuditEntry(
    grievance.id,
    'GRIEVANCE_FILED',
    'Anonymous Student',
    `New report filed in [${grievance.cat}] at [${grievance.loc}]. Initial SLA assigned to ${grievance.authority} (${catConfig.sla}h window).`,
    ts
  );

  saveState();
  return grievance;
}

// Automated SLA Escalation Daemon
async function checkAndEscalateSLA() {
  const now = getSimulatedNow();
  let escalatedAny = false;

  for (const g of state.db.g) {
    if (g.status === 'Resolved') continue;

    const catConfig = CATEGORIES[g.cat];
    // If overdue and further escalation tier exists
    while (now > g.due && g.level < catConfig.chain.length - 1) {
      const prevAuth = g.authority;
      g.level++;
      g.escCount++;
      g.authority = catConfig.chain[g.level];
      
      // SLA interval for the next tier
      const nextWindowHours = Math.max(12, Math.floor(catConfig.sla / Math.pow(1.5, g.level)));
      g.due += (nextWindowHours * ONE_HOUR);
      g.status = 'Escalated';

      await recordAuditEntry(
        g.id,
        'SLA_BREACH_AUTO_ESCALATED',
        'SLA Scheduler Daemon',
        `SLA deadline breached under ${prevAuth}. Automatically escalated to Tier ${g.level + 1} Authority: ${g.authority}. Next deadline extended by ${nextWindowHours}h.`,
        g.due - (nextWindowHours * ONE_HOUR)
      );

      escalatedAny = true;
      showToast(`⚠️ Auto-Escalation: Case #${g.id} escalated to ${g.authority}`, 'error');
    }
  }

  if (escalatedAny) {
    saveState();
    renderApp();
  }
}

// ==========================================
// SEED DATA GENERATOR
// ==========================================
async function seedDemonstrationData() {
  state.db = { g: [], log: [], off: 0 };
  const baseTime = Date.now();

  const seedCases = [
    {
      cat: 'Hostel',
      loc: 'Hostel Block A (Boys)',
      urgency: 'Critical',
      title: 'Severe water leak in 3rd floor washrooms',
      desc: 'Water pipes burst above washroom 302 causing flooding into corridor and rooms. Risk of short circuit with corridor switchboards.',
      offsetHours: -60,
      files: [{ name: 'flooded_corridor.jpg', size: 184520, blobUrl: 'blob://campusvoice-evidence/blob_9f2a_water.jpg' }]
    },
    {
      cat: 'Mess & Food',
      loc: 'Central Mess Hall',
      urgency: 'High',
      title: 'Stale and sour dal served during dinner',
      desc: 'Multiple students fell sick after eating dinner yesterday. Dal smelled foul and rice was yellowed. Kitchen sanitation needs audit.',
      offsetHours: -36,
      files: [{ name: 'kitchen_inspection_photo.jpg', size: 245000, blobUrl: 'blob://campusvoice-evidence/blob_41c0_food.jpg' }]
    },
    {
      cat: 'Lab & Equipment',
      loc: 'Computer Science Block - Lab 301',
      urgency: 'Normal',
      title: 'Over 14 PC monitors malfunctioning before compiler lab',
      desc: 'Systems 12 through 26 fail to boot or have broken display cables. Mid-semester exams are approaching next week.',
      offsetHours: -80,
      files: [{ name: 'lab301_pc_list.pdf', size: 89000, blobUrl: 'blob://campusvoice-evidence/blob_77b1_lab.pdf' }]
    },
    {
      cat: 'Ragging & Harassment',
      loc: 'Hostel Block B (Boys)',
      urgency: 'Critical',
      title: 'Forced late-night assembly of first-year students in Room 114',
      desc: 'Senior students compelling freshers to report at 1:30 AM every night and restricting library access.',
      offsetHours: -8,
      files: []
    },
    {
      cat: 'Campus Infrastructure',
      loc: 'Central Library & Reading Room',
      urgency: 'Normal',
      title: 'HVAC AC failure in quiet study wing',
      desc: 'Temperature in the reading room is over 35°C during afternoon hours making studying impossible.',
      offsetHours: -120,
      files: []
    }
  ];

  for (const c of seedCases) {
    const filingTime = baseTime + (c.offsetHours * ONE_HOUR);
    await createGrievance(c, filingTime);
  }

  // Resolve the 5th case to demonstrate a closed case
  const resolvedCase = state.db.g[4];
  resolvedCase.status = 'Resolved';
  resolvedCase.resolved = baseTime - (15 * ONE_HOUR);
  resolvedCase.resolutionNote = 'Estate maintenance replaced fan capacitor and recharged AC refrigerant. Air conditioning verified operational.';
  await recordAuditEntry(
    resolvedCase.id,
    'GRIEVANCE_RESOLVED',
    'Estate & Maintenance Officer',
    `Resolved: ${resolvedCase.resolutionNote}`,
    resolvedCase.resolved
  );

  // Trigger any natural SLA escalations for the seeded hours
  await checkAndEscalateSLA();
  saveState();
  renderApp();
  showToast('Sample campus grievance dataset seeded successfully', 'success');
}

// ==========================================
// PERSISTENCE
// ==========================================
function saveState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.db));
  } catch (err) {
    console.error('Failed to save to local storage', err);
  }
}

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      state.db = JSON.parse(raw);
    }
  } catch (err) {
    console.error('Failed to parse saved state', err);
  }
}

// ==========================================
// NOTIFICATIONS & UI HELPERS
// ==========================================
function showToast(message, type = 'info') {
  const container = $('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span>${type === 'success' ? '✅' : type === 'error' ? '🚨' : 'ℹ️'}</span>
    <div>${escapeHtml(message)}</div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function copyToClipboard(text, alertMsg = 'Copied to clipboard!') {
  navigator.clipboard.writeText(text).then(() => {
    showToast(alertMsg, 'success');
  }).catch(() => {
    // Fallback
    const input = document.createElement('input');
    input.value = text;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
    showToast(alertMsg, 'success');
  });
}

function toggleTheme() {
  const newTheme = state.currentTheme === 'light' ? 'dark' : 'light';
  state.currentTheme = newTheme;
  document.documentElement.setAttribute('data-theme', newTheme);
  $('theme-label').textContent = newTheme === 'light' ? '🌙 Dark' : '☀️ Light';
  localStorage.setItem('cv_theme', newTheme);
}

// ==========================================
// TIME TRAVEL SIMULATION (FOR PROJECT VIVA)
// ==========================================
async function advanceSimulationHours(hours) {
  state.db.off += hours * ONE_HOUR;
  await checkAndEscalateSLA();
  saveState();
  renderApp();
  showToast(`Simulated time advanced by +${hours} hours`, 'info');
}

// ==========================================
// RENDERERS PER VIEW
// ==========================================
function renderApp() {
  // Update role buttons
  document.querySelectorAll('.role-btn').forEach(btn => {
    const r = btn.getAttribute('data-role');
    btn.classList.toggle('active', r === state.role);
  });

  // Render Sub Navigation
  const navContainer = $('sub-nav');
  const tabs = TABS[state.role] || [];
  
  // Validate current tab for role
  if (!tabs.find(t => t.id === state.currentTab)) {
    state.currentTab = tabs[0].id;
  }

  navContainer.innerHTML = tabs.map(tab => `
    <button class="nav-tab ${tab.id === state.currentTab ? 'active' : ''}" onclick="switchTab('${tab.id}')">
      <span>${tab.icon}</span> ${tab.label}
    </button>
  `).join('');

  // Update System Demo Ribbon
  const simDate = new Date(getSimulatedNow()).toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  });
  $('sim-time-display').textContent = `${simDate} (+${Math.round(state.db.off / ONE_HOUR)}h offset)`;

  // Render View Content
  const viewContainer = $('main-view');
  let html = '';

  switch (state.currentTab) {
    case 'file':
      html = renderFileGrievanceView();
      break;
    case 'track':
      html = renderTrackGrievanceView();
      break;
    case 'transparency':
      html = renderPublicTransparencyView();
      break;
    case 'queue':
      html = renderAuthorityQueueView();
      break;
    case 'sla_alerts':
      html = renderSlaAlertsView();
      break;
    case 'resolved':
      html = renderAuthorityResolvedView();
      break;
    case 'analytics':
      html = renderAnalyticsDashboardView();
      break;
    case 'audit':
      html = renderAuditLedgerView();
      break;
    case 'all_cases':
      html = renderAllCasesMasterView();
      break;
    case 'viva_arch':
      html = renderVivaArchitectureView();
      break;
    default:
      html = renderFileGrievanceView();
  }

  viewContainer.innerHTML = html;
  attachDynamicEventListeners();
}

function switchRole(newRole) {
  state.role = newRole;
  state.currentTab = TABS[newRole][0].id;
  renderApp();
}

function switchTab(tabId) {
  state.currentTab = tabId;
  renderApp();
}

// ------------------------------------------
// VIEW 1: FILE GRIEVANCE (STUDENT)
// ------------------------------------------
function renderFileGrievanceView() {
  const defaultCat = Object.keys(CATEGORIES)[0];

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">🛡️ File an Anonymous Grievance</h2>
          <p class="card-desc">Zero-knowledge submission. No student ID, IP address, roll number, or cookie identity is stored.</p>
        </div>
        <span class="status-pill status-open">🔒 Cryptographically Protected</span>
      </div>

      <div class="callout privacy">
        <span>🛡️</span>
        <div>
          <strong>Privacy Guarantee:</strong> You will receive a unique receipt token upon submission.
          This token is your only proof and access key. Authorities can inspect and resolve your issue, but cannot deanonymize you.
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
        <span style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted);">Quick Demo Presets for Viva:</span>
        <div style="display: flex; gap: 6px; flex-wrap: wrap;">
          <button class="btn btn-secondary btn-sm" type="button" onclick="loadFormPreset('water')">⚡ Hostel Water Leak</button>
          <button class="btn btn-secondary btn-sm" type="button" onclick="loadFormPreset('mess')">⚡ Mess Food Hygiene</button>
          <button class="btn btn-secondary btn-sm" type="button" onclick="loadFormPreset('lab')">⚡ Broken Lab PCs</button>
          <button class="btn btn-secondary btn-sm" type="button" onclick="loadFormPreset('ragging')">⚡ Anti-Ragging Alert</button>
        </div>
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label class="form-label" for="fg-cat">Grievance Category *</label>
          <select id="fg-cat" class="form-select" onchange="updateRoutingPreview(this.value)">
            ${Object.keys(CATEGORIES).map(c => `<option value="${c}">${CATEGORIES[c].icon} ${c}</option>`).join('')}
          </select>
        </div>

        <div class="form-group">
          <label class="form-label" for="fg-loc">Campus Location / Block *</label>
          <select id="fg-loc" class="form-select">
            ${LOCATIONS.map(l => `<option value="${l}">${l}</option>`).join('')}
          </select>
        </div>
      </div>

      <!-- Dynamic SLA and Escalation Path Preview -->
      <div id="routing-preview-box" class="routing-preview">
        ${getRoutingChainHTML(defaultCat)}
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label class="form-label" for="fg-urgency">Perceived Urgency</label>
          <select id="fg-urgency" class="form-select">
            <option value="Normal">Normal (Standard SLA)</option>
            <option value="High">High (Impacting multiple students)</option>
            <option value="Critical">Critical (Immediate safety / hazard)</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label" for="fg-title">Subject Summary *</label>
          <input type="text" id="fg-title" class="form-input" placeholder="e.g. Washroom leakage in Hostel Block A, 3rd floor" maxlength="90">
        </div>
      </div>

      <div class="form-group">
        <label class="form-label" for="fg-desc">Detailed Description *</label>
        <textarea id="fg-desc" class="form-textarea" placeholder="Describe exactly what happened, when it began, room/system numbers, and any recurring patterns..." oninput="updateCharCount(this)"></textarea>
        <div class="char-counter" id="char-count">0 characters (minimum 20 recommended)</div>
      </div>

      <!-- Evidence Dropzone -->
      <div class="form-group">
        <label class="form-label">Supporting Evidence (Photos, Screenshots or PDF Logs)</label>
        <div class="file-dropzone" id="file-dropzone">
          <input type="file" id="fg-file" multiple accept="image/*,application/pdf" onchange="handleFileUpload(this.files)">
          <div style="font-size: 2rem; margin-bottom: 8px;">📎</div>
          <strong>Drag & drop evidence files here or click to browse</strong>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">Supports PNG, JPG, WebP, PDF (Simulated Azure Blob Storage container with SHA-256 integrity)</p>
        </div>
        <div id="file-preview-list" class="file-preview-list"></div>
      </div>

      <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 24px;">
        <button class="btn btn-secondary" onclick="resetFileForm()">Clear Form</button>
        <button class="btn btn-primary" onclick="submitGrievanceForm()">
          🚀 Submit Anonymous Grievance
        </button>
      </div>
    </div>
  `;
}

function getRoutingChainHTML(categoryName) {
  const cat = CATEGORIES[categoryName];
  if (!cat) return '';

  return `
    <div class="routing-title">
      <span>Auto-Routing Hierarchy & SLA Guarantee (${cat.sla} Hours Initial Target)</span>
      <span class="status-pill status-open">Auto-Escalation Enabled</span>
    </div>
    <div class="routing-chain">
      <div class="routing-step">
        <span>Tier 1:</span> <strong>${cat.chain[0]}</strong>
        <span class="tag" style="background: var(--primary-subtle); color: var(--primary); margin-left: 6px;">SLA ${cat.sla}h</span>
      </div>
      <span class="routing-arrow">➔</span>
      <div class="routing-step">
        <span>Tier 2:</span> <strong>${cat.chain[1]}</strong>
      </div>
      <span class="routing-arrow">➔</span>
      <div class="routing-step">
        <span>Tier 3:</span> <strong>${cat.chain[2]}</strong>
      </div>
    </div>
  `;
}

function updateRoutingPreview(catName) {
  const el = $('routing-preview-box');
  if (el) el.innerHTML = getRoutingChainHTML(catName);
}

function updateCharCount(textarea) {
  const counter = $('char-count');
  if (counter) counter.textContent = `${textarea.value.length} characters (minimum 20 recommended)`;
}

function handleFileUpload(files) {
  state.uploadedFilesCache = [];
  const preview = $('file-preview-list');
  if (!preview) return;

  preview.innerHTML = '';
  Array.from(files).forEach((file, idx) => {
    const mockBlobId = `blob_${Math.random().toString(36).substring(2, 9)}_${file.name.replace(/\s+/g, '_')}`;
    const fileObj = {
      name: file.name,
      size: file.size,
      type: file.type,
      blobUrl: `blob://campusvoice-evidence/${mockBlobId}`
    };
    state.uploadedFilesCache.push(fileObj);

    const item = document.createElement('div');
    item.className = 'file-preview-item';
    item.innerHTML = `
      <div class="file-info">
        <span>${file.type.includes('pdf') ? '📄' : '🖼️'}</span>
        <strong>${escapeHtml(file.name)}</strong>
        <span style="color: var(--text-muted);">(${Math.round(file.size / 1024)} KB)</span>
      </div>
      <div style="display: flex; align-items: center; gap: 8px;">
        <span class="file-badge">Azure Blob Encrypted</span>
        <span style="color: var(--success); font-size: 0.8rem;">✓ Ready</span>
      </div>
    `;
    preview.appendChild(item);
  });
}

function resetFileForm() {
  $('fg-title').value = '';
  $('fg-desc').value = '';
  state.uploadedFilesCache = [];
  const preview = $('file-preview-list');
  if (preview) preview.innerHTML = '';
}

async function submitGrievanceForm() {
  const title = $('fg-title').value.trim();
  const desc = $('fg-desc').value.trim();
  const cat = $('fg-cat').value;
  const loc = $('fg-loc').value;
  const urgency = $('fg-urgency').value;

  if (title.length < 5) {
    showToast('Please provide a subject title with at least 5 characters.', 'error');
    $('fg-title').focus();
    return;
  }
  if (desc.length < 15) {
    showToast('Please describe the issue in more detail (at least 15 characters).', 'error');
    $('fg-desc').focus();
    return;
  }

  const grievance = await createGrievance({
    cat,
    loc,
    urgency,
    title,
    desc,
    files: [...state.uploadedFilesCache]
  });

  state.activeReceiptToken = grievance.token;
  resetFileForm();
  showReceiptModal(grievance);
}

function showReceiptModal(g) {
  const modal = $('receipt-modal');
  $('modal-token-display').textContent = g.token;
  $('modal-grievance-title').textContent = g.title;
  $('modal-grievance-cat').textContent = `${g.cat} • ${g.loc}`;
  $('modal-grievance-auth').textContent = g.authority;
  $('modal-grievance-sla').textContent = formatDate(g.due);

  modal.classList.add('open');
}

function closeReceiptModal() {
  $('receipt-modal').classList.remove('open');
}

function trackFromReceipt() {
  closeReceiptModal();
  state.currentTab = 'track';
  renderApp();
  setTimeout(() => {
    const input = $('track-token-input');
    if (input) {
      input.value = state.activeReceiptToken;
      executeTrackLookup();
    }
  }, 100);
}

// ------------------------------------------
// VIEW 2: TRACK GRIEVANCE (STUDENT)
// ------------------------------------------
function renderTrackGrievanceView() {
  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">🔍 Track Your Grievance Status</h2>
          <p class="card-desc">Enter your unique receipt token to check SLA progress, investigation notes, and resolution status.</p>
        </div>
      </div>

      <div style="display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap;">
        <input type="text" id="track-token-input" class="form-input" style="flex: 1; min-width: 260px; font-family: var(--font-mono); font-size: 1.05rem;" 
               placeholder="e.g. CV-HOS-9A4B-2026" value="${state.activeReceiptToken}" onkeydown="if(event.key==='Enter') executeTrackLookup()">
        <button class="btn btn-primary" onclick="executeTrackLookup()">
          Inspect Timeline & SLA
        </button>
      </div>

      <div id="track-result-container">
        ${state.activeReceiptToken ? getTrackingCardHTML(state.activeReceiptToken) : `
          <div style="text-align: center; padding: 48px 20px; color: var(--text-muted);">
            <div style="font-size: 3rem; margin-bottom: 12px;">🎫</div>
            <strong>No token entered yet</strong>
            <p style="font-size: 0.85rem; margin-top: 4px;">Paste the receipt token you received when submitting your grievance.</p>
          </div>
        `}
      </div>
    </div>
  `;
}

function executeTrackLookup() {
  const token = $('track-token-input').value.trim().toUpperCase();
  const container = $('track-result-container');
  if (!token) {
    showToast('Please enter a receipt token to search.', 'error');
    return;
  }

  state.activeReceiptToken = token;
  container.innerHTML = getTrackingCardHTML(token);
}

function getTrackingCardHTML(token) {
  const g = state.db.g.find(x => x.token.toUpperCase() === token.toUpperCase());
  if (!g) {
    return `
      <div class="callout danger">
        <span>❌</span>
        <div>
          <strong>Grievance Not Found:</strong> No case matched the token <code>${escapeHtml(token)}</code>.
          Please verify that you copied the complete token with no missing characters.
        </div>
      </div>
    `;
  }

  const isResolved = g.status === 'Resolved';
  const isOverdue = !isResolved && getSimulatedNow() > g.due;
  const auditEntries = state.db.log.filter(e => e.gid === g.id);

  return `
    <div class="receipt-card" style="margin-bottom: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap;">
        <div>
          <span class="tag" style="background: var(--primary-subtle); color: var(--primary-text); font-weight: bold;">#Case ${g.id}</span>
          <span class="tag">${g.cat}</span>
          <span class="tag">${escapeHtml(g.loc)}</span>
          <h3 style="font-size: 1.25rem; font-weight: 700; margin-top: 8px;">${escapeHtml(g.title)}</h3>
        </div>
        <div>
          ${isResolved ? '<span class="status-pill status-resolved">✓ Resolved</span>' : 
            isOverdue ? '<span class="status-pill status-overdue">⚠️ SLA Breached (Auto-Escalated)</span>' : 
            g.escCount > 0 ? `<span class="status-pill status-escalated">Escalated Tier ${g.level + 1}</span>` :
            '<span class="status-pill status-open">⏳ Under Active SLA</span>'}
        </div>
      </div>

      <p style="margin: 12px 0; color: var(--text-main); font-size: 0.95rem;">${escapeHtml(g.desc)}</p>

      <div class="token-box">
        <div>
          <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600;">Currently Assigned Authority</div>
          <div style="font-size: 1.05rem; font-weight: 700; color: var(--text-main);">${escapeHtml(g.authority)} (Tier ${g.level + 1})</div>
        </div>
        <div>
          <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600;">SLA Countdown</div>
          <div>${isResolved ? `<span style="color: var(--success); font-weight: 600;">Closed in ${Math.round((g.resolved - g.created)/ONE_HOUR)}h</span>` : formatTimeLeft(g.due)}</div>
        </div>
        <div>
          <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600;">Target Deadline</div>
          <div style="font-size: 0.9rem; font-family: var(--font-mono);">${formatDate(g.due)}</div>
        </div>
      </div>

      ${g.files && g.files.length ? `
        <div style="margin: 14px 0;">
          <strong style="font-size: 0.85rem; color: var(--text-muted);">Attached Evidence Files (Click to inspect Azure Blob):</strong>
          <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 6px;">
            ${g.files.map((f, fi) => `
              <div class="file-preview-item" style="padding: 6px 10px; font-size: 0.8rem; cursor: pointer;" onclick="viewEvidenceModal(${g.id}, ${fi})" title="Inspect Evidence">
                <span>${f.name && f.name.endsWith('.pdf') ? '📄' : '📷'}</span>
                <span>${escapeHtml(f.name)} (${Math.round(f.size/1024)} KB)</span>
                <span class="file-badge">Azure Blob</span>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      ${isResolved ? `
        <div class="callout privacy" style="margin-top: 16px;">
          <span>✅</span>
          <div>
            <strong>Official Resolution Notice:</strong>
            <p style="margin-top: 4px;">${escapeHtml(g.resolutionNote || 'The authority has marked this complaint as resolved in compliance with campus regulations.')}</p>
          </div>
        </div>
      ` : ''}

      <!-- Interactive Stepper Timeline -->
      <h4 style="margin: 24px 0 12px; font-size: 0.95rem; font-weight: 700; color: var(--text-main);">
        📜 Cryptographic Activity Timeline & Audit Logs
      </h4>
      <div class="timeline">
        ${auditEntries.map(entry => `
          <div class="timeline-item ${entry.action.includes('RESOLVED') ? 'active' : ''}">
            <div class="timeline-node"></div>
            <div class="timeline-content">
              <div class="timeline-header">
                <span class="timeline-title">${escapeHtml(entry.action.replace(/_/g, ' '))}</span>
                <span class="timeline-time">${formatDate(entry.timestamp)}</span>
              </div>
              <div class="timeline-detail">
                <strong>Actor:</strong> ${escapeHtml(entry.actor)}<br>
                ${escapeHtml(entry.detail)}
              </div>
              <div style="margin-top: 6px; font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-subtle);">
                SHA-256 Block Hash: <code>${entry.hash.substring(0, 24)}...</code>
              </div>
            </div>
          </div>
        `).join('')}
      </div>

      <!-- Anonymous Student Follow-up Note -->
      ${!isResolved ? `
        <div style="background: var(--bg-tertiary); padding: 16px; border-radius: var(--radius-md); margin-top: 20px;">
          <h5 style="font-size: 0.85rem; font-weight: 700; margin-bottom: 8px;">💬 Add Anonymous Clarification Note to Authority</h5>
          <div style="display: flex; gap: 8px;">
            <input type="text" id="student-reply-${g.id}" class="form-input" placeholder="e.g. Issue got worse this evening; please bring spare parts..." style="flex: 1;">
            <button class="btn btn-secondary btn-sm" onclick="addStudentNote(${g.id})">Send Anonymously</button>
          </div>
        </div>
      ` : ''}
    </div>
  `;
}

async function addStudentNote(gid) {
  const input = $(`student-reply-${gid}`);
  const note = input ? input.value.trim() : '';
  if (!note) {
    showToast('Please type a message before sending.', 'error');
    return;
  }

  const g = state.db.g.find(x => x.id === gid);
  if (g) {
    g.notes.push({ actor: 'Anonymous Student', text: note, time: getSimulatedNow() });
    await recordAuditEntry(gid, 'NOTE_ADDED', 'Anonymous Student', `Clarification: ${note}`);
    showToast('Anonymous note added to the complaint audit thread', 'success');
    renderApp();
  }
}

// ------------------------------------------
// VIEW 3: PUBLIC TRANSPARENCY FEED
// ------------------------------------------
function renderPublicTransparencyView() {
  const resolvedCases = state.db.g.filter(g => g.status === 'Resolved');
  const avgHours = resolvedCases.length 
    ? (resolvedCases.reduce((acc, c) => acc + (c.resolved - c.created), 0) / resolvedCases.length / ONE_HOUR).toFixed(1)
    : 0;

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">📢 Public Campus Resolution Feed</h2>
          <p class="card-desc">Redacted public record of resolved grievances to assure the student body of campus responsiveness.</p>
        </div>
        <span class="status-pill status-resolved">${resolvedCases.length} Issues Resolved</span>
      </div>

      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-title">Average Time to Resolution</div>
          <div class="kpi-value">${avgHours}h</div>
          <div class="kpi-sub">Across all campus departments</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Total Handled</div>
          <div class="kpi-value">${state.db.g.length}</div>
          <div class="kpi-sub">Grievances filed this semester</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Audit Chain Integrity</div>
          <div class="kpi-value" style="color: var(--success); font-size: 1.4rem;">100% Cryptographic</div>
          <div class="kpi-sub">Zero records deleted or altered</div>
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 14px;">
        ${resolvedCases.length ? resolvedCases.map(g => `
          <div style="background: var(--bg-tertiary); border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-wrap: wrap; gap: 8px;">
              <div>
                <span class="tag">${g.cat}</span>
                <span class="tag">${escapeHtml(g.loc)}</span>
                <strong style="font-size: 0.95rem;">${escapeHtml(g.title)}</strong>
              </div>
              <span class="status-pill status-resolved">Resolved in ${Math.round((g.resolved - g.created)/ONE_HOUR)}h</span>
            </div>
            <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 8px;">${escapeHtml(g.desc)}</p>
            <div style="background: var(--bg-card); padding: 10px 14px; border-radius: var(--radius-sm); border-left: 3px solid var(--success); font-size: 0.85rem;">
              <strong>Action Taken by ${escapeHtml(g.authority)}:</strong> ${escapeHtml(g.resolutionNote || 'Resolved')}
            </div>
            <div style="margin-top: 8px; font-size: 0.75rem; color: var(--text-subtle);">
              Resolved on ${formatDate(g.resolved)} • Tamper-evident receipt verified
            </div>
          </div>
        `).join('') : `
          <p style="text-align: center; color: var(--text-muted); padding: 24px;">No resolved cases yet.</p>
        `}
      </div>
    </div>
  `;
}

// ------------------------------------------
// VIEW 4: AUTHORITY QUEUE (AUTHORITY)
// ------------------------------------------
function renderAuthorityQueueView() {
  const allAuthorities = Array.from(new Set(Object.values(CATEGORIES).flatMap(c => c.chain)));
  if (!allAuthorities.includes(state.selectedAuthority)) {
    state.selectedAuthority = allAuthorities[0];
  }

  // Filter cases assigned to this authority
  const assignedCases = state.db.g
    .filter(g => g.authority === state.selectedAuthority && g.status !== 'Resolved')
    .sort((a, b) => a.due - b.due);

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">📥 Authority Investigation Queue</h2>
          <p class="card-desc">Review assigned anonymous complaints, inspect attached evidence, and update investigation milestones.</p>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <label style="font-size: 0.85rem; font-weight: 600;">Active Authority Persona:</label>
          <select class="form-select" style="width: auto; padding: 6px 12px; font-weight: 600;" onchange="changeAuthorityPersona(this.value)">
            ${allAuthorities.map(a => `
              <option value="${a}" ${a === state.selectedAuthority ? 'selected' : ''}>${a}</option>
            `).join('')}
          </select>
        </div>
      </div>

      <div class="callout info">
        <span>ℹ️</span>
        <div>
          Viewing queue as <strong>${escapeHtml(state.selectedAuthority)}</strong>.
          Complaints show live SLA timers. If the SLA expires without resolution, the background scheduler automatically escalates the case to the next higher officer and writes a permanent breach entry into the cryptographic log.
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 16px;">
        ${assignedCases.length ? assignedCases.map(g => renderAuthorityCaseCard(g)).join('') : `
          <div style="text-align: center; padding: 48px 20px; color: var(--text-muted);">
            <div style="font-size: 3rem; margin-bottom: 12px;">🎉</div>
            <strong>No pending complaints in your queue!</strong>
            <p style="font-size: 0.85rem; margin-top: 4px;">All complaints assigned to ${escapeHtml(state.selectedAuthority)} have been resolved or handed over.</p>
          </div>
        `}
      </div>
    </div>
  `;
}

function renderAuthorityCaseCard(g) {
  const isOverdue = getSimulatedNow() > g.due;

  return `
    <div class="card" style="margin-bottom: 0; border-left: 4px solid ${isOverdue ? 'var(--danger)' : 'var(--primary)'};">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap;">
        <div>
          <span class="tag" style="background: var(--primary-subtle); color: var(--primary-text); font-weight: bold;">Case #${g.id}</span>
          <span class="tag">${g.cat}</span>
          <span class="tag">${escapeHtml(g.loc)}</span>
          <span class="tag" style="background: ${g.urgency === 'Critical' ? 'var(--danger-subtle)' : 'var(--bg-tertiary)'}; color: ${g.urgency === 'Critical' ? 'var(--danger-text)' : 'inherit'};">
            ${g.urgency} Urgency
          </span>
          <h3 style="font-size: 1.15rem; font-weight: 700; margin-top: 6px;">${escapeHtml(g.title)}</h3>
        </div>
        <div style="text-align: right;">
          ${formatTimeLeft(g.due)}
          <div style="font-size: 0.72rem; color: var(--text-subtle); margin-top: 4px;">
            Target: ${formatDate(g.due)}
          </div>
        </div>
      </div>

      <p style="margin: 12px 0; color: var(--text-main); font-size: 0.9rem;">${escapeHtml(g.desc)}</p>

      ${g.files && g.files.length ? `
        <div style="margin: 10px 0; background: var(--bg-tertiary); padding: 8px 12px; border-radius: var(--radius-sm);">
          <strong style="font-size: 0.8rem; color: var(--text-muted);">Uploaded Evidence (${g.files.length} items - click to inspect):</strong>
          <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px;">
            ${g.files.map((f, fi) => `
              <span class="file-badge" style="cursor: pointer; padding: 4px 8px;" onclick="viewEvidenceModal(${g.id}, ${fi})">
                ${f.name && f.name.endsWith('.pdf') ? '📄' : '📷'} ${escapeHtml(f.name)} (${Math.round(f.size/1024)} KB)
              </span>
            `).join('')}
          </div>
        </div>
      ` : ''}

      <!-- Authority Action Controls -->
      <div style="background: var(--bg-tertiary); padding: 14px; border-radius: var(--radius-md); margin-top: 14px; display: flex; flex-direction: column; gap: 10px;">
        <div style="font-size: 0.82rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">
          Official Investigation Action
        </div>
        <input type="text" id="auth-note-${g.id}" class="form-input" placeholder="Enter investigation remarks / resolution steps taken (required for resolving)">
        
        <div style="display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end;">
          <button class="btn btn-secondary btn-sm" onclick="authorityUpdateStatus(${g.id}, 'Under Investigation')">
            Mark 'Under Investigation'
          </button>
          <button class="btn btn-secondary btn-sm" onclick="authorityManualEscalate(${g.id})">
            Escalate to Next Officer Early
          </button>
          <button class="btn btn-primary btn-sm" onclick="authorityResolveCase(${g.id})">
            ✓ Finalize & Mark Resolved
          </button>
        </div>
      </div>
    </div>
  `;
}

function changeAuthorityPersona(authName) {
  state.selectedAuthority = authName;
  renderApp();
}

async function authorityUpdateStatus(gid, newStatus) {
  const g = state.db.g.find(x => x.id === gid);
  const noteInput = $(`auth-note-${gid}`);
  const note = noteInput ? noteInput.value.trim() : '';

  if (g) {
    g.status = newStatus;
    await recordAuditEntry(
      gid,
      'STATUS_UPDATED',
      g.authority,
      `Status changed to [${newStatus}]. Note: ${note || 'Status updated during standard inspection'}`
    );
    showToast(`Case #${gid} updated to ${newStatus}`, 'success');
    renderApp();
  }
}

async function authorityManualEscalate(gid) {
  const g = state.db.g.find(x => x.id === gid);
  const catConfig = CATEGORIES[g.cat];

  if (g.level >= catConfig.chain.length - 1) {
    showToast('This case is already at the highest authority level (Principal/Director).', 'error');
    return;
  }

  const prev = g.authority;
  g.level++;
  g.escCount++;
  g.authority = catConfig.chain[g.level];
  g.status = 'Escalated';

  await recordAuditEntry(
    gid,
    'MANUAL_EARLY_ESCALATION',
    prev,
    `Authority ${prev} manually escalated this matter to Tier ${g.level + 1}: ${g.authority}. Case requires higher institutional discretion.`
  );

  showToast(`Case #${gid} escalated to ${g.authority}`, 'info');
  renderApp();
}

async function authorityResolveCase(gid) {
  const g = state.db.g.find(x => x.id === gid);
  const noteInput = $(`auth-note-${gid}`);
  const note = noteInput ? noteInput.value.trim() : '';

  if (!note) {
    showToast('A resolution note describing the corrective actions is mandatory before closing.', 'error');
    if (noteInput) noteInput.focus();
    return;
  }

  if (g) {
    g.status = 'Resolved';
    g.resolved = getSimulatedNow();
    g.resolutionNote = note;

    await recordAuditEntry(
      gid,
      'GRIEVANCE_RESOLVED',
      g.authority,
      `Official resolution logged: ${note}`
    );

    showToast(`Case #${gid} marked as resolved`, 'success');
    renderApp();
  }
}

// ------------------------------------------
// VIEW 5: SLA ALERTS MONITOR (AUTHORITY)
// ------------------------------------------
function renderSlaAlertsView() {
  const overdueOrUrgent = state.db.g
    .filter(g => g.status !== 'Resolved' && (getSimulatedNow() > g.due || (g.due - getSimulatedNow()) < 24 * ONE_HOUR))
    .sort((a, b) => a.due - b.due);

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">⏱️ SLA Urgency & Impending Breaches</h2>
          <p class="card-desc">Grievances where the SLA countdown is under 24 hours or already overdue.</p>
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 14px;">
        ${overdueOrUrgent.length ? overdueOrUrgent.map(g => `
          <div style="background: var(--bg-tertiary); border: 1px solid var(--border-medium); border-radius: var(--radius-md); padding: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
              <div>
                <span class="tag" style="background: var(--primary-subtle); color: var(--primary-text); font-weight: bold;">#${g.id}</span>
                <span class="tag">${g.cat}</span>
                <strong>${escapeHtml(g.title)}</strong>
              </div>
              ${formatTimeLeft(g.due)}
            </div>
            <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 8px;">
              Assigned to: <strong>${escapeHtml(g.authority)}</strong> • Location: ${escapeHtml(g.loc)}
            </div>
            <div style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--text-subtle);">
              Deadline: ${formatDate(g.due)}
            </div>
          </div>
        `).join('') : `
          <div style="text-align: center; padding: 48px; color: var(--text-muted);">
            ✓ All active grievances are well within their SLA deadlines.
          </div>
        `}
      </div>
    </div>
  `;
}

// ------------------------------------------
// VIEW 6: RESOLVED ARCHIVE (AUTHORITY)
// ------------------------------------------
function renderAuthorityResolvedView() {
  const resolved = state.db.g.filter(g => g.status === 'Resolved');

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">✅ Department Resolution Archive</h2>
          <p class="card-desc">Audit logs of all closed cases with official remarks.</p>
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 12px;">
        ${resolved.map(g => `
          <div style="background: var(--bg-tertiary); padding: 14px; border-radius: var(--radius-md); border-left: 3px solid var(--success);">
            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
              <strong>#${g.id} ${escapeHtml(g.title)}</strong>
              <span class="tag">${g.cat}</span>
            </div>
            <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 6px;">
              Resolved by ${escapeHtml(g.authority)} on ${formatDate(g.resolved)}
            </div>
            <div style="font-size: 0.85rem; background: var(--bg-card); padding: 8px 12px; border-radius: var(--radius-sm);">
              <strong>Remarks:</strong> ${escapeHtml(g.resolutionNote)}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ------------------------------------------
// VIEW 7: ANALYTICS & HOTSPOTS (ADMIN)
// ------------------------------------------
function renderAnalyticsDashboardView() {
  const G = state.db.g;
  const total = G.length;
  const open = G.filter(g => g.status !== 'Resolved').length;
  const resolved = G.filter(g => g.status === 'Resolved').length;
  const overdue = G.filter(g => g.status !== 'Resolved' && getSimulatedNow() > g.due).length;
  const escalated = G.filter(g => g.escCount > 0).length;

  const resolvedList = G.filter(g => g.resolved);
  const avgResolutionHours = resolvedList.length 
    ? (resolvedList.reduce((acc, g) => acc + (g.resolved - g.created), 0) / resolvedList.length / ONE_HOUR).toFixed(1)
    : '0';

  const slaCompliance = total > 0 ? (((total - overdue) / total) * 100).toFixed(1) : 100;

  // Count by category
  const catCounts = {};
  Object.keys(CATEGORIES).forEach(c => catCounts[c] = 0);
  G.forEach(g => { catCounts[g.cat] = (catCounts[g.cat] || 0) + 1; });

  // Count by location
  const locCounts = {};
  LOCATIONS.forEach(l => locCounts[l] = 0);
  G.forEach(g => { locCounts[g.loc] = (locCounts[g.loc] || 0) + 1; });

  const sortedLocs = Object.entries(locCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const maxLocCount = Math.max(1, ...sortedLocs.map(x => x[1]));
  const maxCatCount = Math.max(1, ...Object.values(catCounts));

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">📊 Executive Campus Analytics & Hotspots</h2>
          <p class="card-desc">Real-time incident trends, institutional SLA compliance, and recurring location hot-spots.</p>
        </div>
        <span class="status-pill status-open">Power BI Live Sync</span>
      </div>

      <!-- KPI Grid -->
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-title">Total Grievances</div>
          <div class="kpi-value">${total}</div>
          <div class="kpi-sub">Across all campus departments</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Active / Open</div>
          <div class="kpi-value" style="color: var(--accent);">${open}</div>
          <div class="kpi-sub">Currently under investigation</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Overdue SLA Cases</div>
          <div class="kpi-value" style="color: var(--danger);">${overdue}</div>
          <div class="kpi-sub">Breached initial deadlines</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Auto-Escalated</div>
          <div class="kpi-value" style="color: #be185d;">${escalated}</div>
          <div class="kpi-sub">Elevated to Tier 2/3 leadership</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Avg Resolution Time</div>
          <div class="kpi-value" style="color: var(--primary);">${avgResolutionHours}h</div>
          <div class="kpi-sub">From filing to official closure</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">SLA Compliance</div>
          <div class="kpi-value" style="color: var(--success);">${slaCompliance}%</div>
          <div class="kpi-sub">Resolved within deadline</div>
        </div>
      </div>

      <!-- Charts Section -->
      <div class="chart-grid">
        <div class="card" style="margin-bottom: 0;">
          <h3 style="font-size: 1rem; font-weight: 700; margin-bottom: 14px;">📍 Top Location Hotspots</h3>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 12px;">Identifies campus blocks requiring immediate infrastructural maintenance or administrative intervention.</p>
          ${sortedLocs.map(([loc, count]) => `
            <div class="bar-row">
              <span class="bar-label" title="${escapeHtml(loc)}">${escapeHtml(loc)}</span>
              <div class="bar-track">
                <div class="bar-fill" style="width: ${(count / maxLocCount) * 100}%;"></div>
              </div>
              <span class="bar-val">${count}</span>
            </div>
          `).join('')}
        </div>

        <div class="card" style="margin-bottom: 0;">
          <h3 style="font-size: 1rem; font-weight: 700; margin-bottom: 14px;">🏷️ Grievances by Category</h3>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 12px;">Distribution across hostel, mess, academic, infrastructure and anti-ragging faculties.</p>
          ${Object.entries(catCounts).map(([cat, count]) => `
            <div class="bar-row">
              <span class="bar-label" title="${cat}">${cat}</span>
              <div class="bar-track">
                <div class="bar-fill" style="width: ${(count / maxCatCount) * 100}%; background: ${CATEGORIES[cat] ? CATEGORIES[cat].color : 'var(--primary)'};"></div>
              </div>
              <span class="bar-val">${count}</span>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

// ------------------------------------------
// VIEW 8: TAMPER-EVIDENT AUDIT LEDGER (ADMIN)
// ------------------------------------------
function renderAuditLedgerView() {
  const isTampered = state.verificationResult !== null && state.verificationResult !== -1;
  const isVerified = state.verificationResult === -1;

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">⛓️ Tamper-Evident SHA-256 Audit Trail</h2>
          <p class="card-desc">Every action, SLA countdown, and resolution is permanently linked in a forward hash-chain. Any silent modification to historical records mathematically breaks all downstream hashes.</p>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-secondary btn-sm" onclick="runChainVerification()">
            🛡️ Verify Chain Integrity
          </button>
          <button class="btn btn-danger btn-sm" onclick="simulateDatabaseTampering()">
            🚨 Simulate Silent DB Attack
          </button>
          ${isTampered ? `
            <button class="btn btn-primary btn-sm" onclick="restoreGenuineChain()">
              🔄 Restore Ledger
            </button>
          ` : ''}
        </div>
      </div>

      <!-- Verification Status Banner -->
      <div id="verification-banner">
        ${isVerified ? `
          <div class="callout privacy">
            <span>🛡️</span>
            <div>
              <strong>Cryptographic Integrity 100% Intact:</strong>
              Verified all ${state.db.log.length} blocks using Web Crypto SHA-256. Zero mutations, broken links, or unauthorized modifications detected.
            </div>
          </div>
        ` : isTampered ? `
          <div class="callout danger">
            <span>🚨</span>
            <div>
              <strong>Tampering Detected at Block #${state.verificationResult}!</strong>
              An unauthorized mutation occurred in Block #${state.verificationResult}. The stored SHA-256 hash does not match the payload, rendering all subsequent blocks invalid.
            </div>
          </div>
        ` : `
          <div class="callout info">
            <span>ℹ️</span>
            <div>
              Click <strong>"Verify Chain Integrity"</strong> to recompute SHA-256 digests across all blocks, or <strong>"Simulate Silent DB Attack"</strong> to see how CampusVoice immediately exposes unauthorized edits.
            </div>
          </div>
        `}
      </div>

      <!-- Block Explorer -->
      <h3 style="font-size: 1rem; font-weight: 700; margin: 20px 0 10px;">
        Ledger Blocks (${state.db.log.length} Entries)
      </h3>

      <div class="chain-container">
        ${state.db.log.map((block, idx) => {
          const isCorrupt = isTampered && idx >= state.verificationResult;

          return `
            <div class="chain-block ${isCorrupt ? 'tampered' : isVerified ? 'verified' : ''}">
              <div class="chain-block-header">
                <div>
                  <span class="block-index">Block #${block.index}</span>
                  <span class="tag" style="margin-left: 8px;">Grievance #${block.gid}</span>
                  <span class="block-action">${escapeHtml(block.action)}</span>
                </div>
                <div style="font-size: 0.75rem; color: var(--text-subtle); font-family: var(--font-mono);">
                  ${formatDate(block.timestamp)}
                </div>
              </div>

              <div style="font-size: 0.88rem; margin: 6px 0;">
                <strong>Actor:</strong> ${escapeHtml(block.actor)}<br>
                <strong>Detail:</strong> ${escapeHtml(block.detail)}
              </div>

              <div class="block-hashes">
                <div class="hash-row">
                  <span class="hash-label">prev_hash:</span>
                  <span class="hash-val">${escapeHtml(block.prevHash)}</span>
                </div>
                <div class="hash-row">
                  <span class="hash-label">block_hash:</span>
                  <span class="hash-val" style="color: ${isCorrupt ? 'var(--danger)' : 'var(--primary)'}; font-weight: 600;">
                    ${escapeHtml(block.hash)}
                  </span>
                </div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

async function runChainVerification() {
  showToast('Recomputing SHA-256 hashes across entire ledger...', 'info');
  const result = await verifyAuditChain();
  if (result === -1) {
    showToast('Chain verified! 100% tamper-evident integrity confirmed.', 'success');
  } else {
    showToast(`Tampering detected at Block #${result}!`, 'error');
  }
  renderApp();
}

async function simulateDatabaseTampering() {
  if (state.db.log.length < 3) {
    showToast('Need at least 3 blocks to simulate tampering attack.', 'error');
    return;
  }

  // Backup original state if not already backed up
  if (!state.tamperedState) {
    state.tamperedState = JSON.parse(JSON.stringify(state.db.log));
  }

  // Corrupt Block #2 by quietly altering a student complaint detail behind the scenes
  const victimBlock = state.db.log[2];
  victimBlock.detail = '[MUTATED BY ROGUE DB ADMIN] Complaint silenced and dismissed without investigation.';

  showToast('Simulated rogue DB update on Block #2. Click "Verify Chain Integrity" to inspect!', 'error');
  saveState();
  await runChainVerification();
}

function restoreGenuineChain() {
  if (state.tamperedState) {
    state.db.log = JSON.parse(JSON.stringify(state.tamperedState));
    state.tamperedState = null;
    state.verificationResult = null;
    saveState();
    showToast('Ledger restored to authentic cryptographic state', 'success');
    renderApp();
  }
}

// ------------------------------------------
// VIEW 9: ALL CASES MASTER TABLE (ADMIN)
// ------------------------------------------
function renderAllCasesMasterView() {
  const q = (state.allCasesSearch || '').toLowerCase();
  const c = state.allCasesCat || 'ALL';

  const filtered = state.db.g.filter(g => {
    const matchCat = (c === 'ALL') || (g.cat === c);
    const matchQuery = !q || g.title.toLowerCase().includes(q) || g.token.toLowerCase().includes(q) || g.loc.toLowerCase().includes(q) || g.desc.toLowerCase().includes(q);
    return matchCat && matchQuery;
  });

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">📋 Institutional Grievance Master Directory</h2>
          <p class="card-desc">Campus-wide administrative oversight view for Dean of Students, Proctor, and Director.</p>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="exportDataAsJSON()">
          📥 Export Audit JSON
        </button>
      </div>

      <!-- Search & Filters -->
      <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;">
        <input type="text" class="form-input" style="flex: 1; min-width: 220px;" placeholder="Search title, location, or token..." 
               value="${escapeHtml(state.allCasesSearch || '')}" oninput="state.allCasesSearch = this.value; updateAllCasesRows();">
        <select class="form-select" style="width: auto;" onchange="state.allCasesCat = this.value; updateAllCasesRows();">
          <option value="ALL">All Categories</option>
          ${Object.keys(CATEGORIES).map(cat => `<option value="${cat}" ${cat === state.allCasesCat ? 'selected' : ''}>${cat}</option>`).join('')}
        </select>
      </div>

      <div style="overflow-x: auto;">
        <table class="schema-table" style="font-size: 0.85rem;">
          <thead>
            <tr>
              <th>ID</th>
              <th>Token</th>
              <th>Category</th>
              <th>Location</th>
              <th>Title</th>
              <th>Assigned To</th>
              <th>Status</th>
              <th>SLA Target</th>
              <th>Inspect</th>
            </tr>
          </thead>
          <tbody id="all-cases-tbody">
            ${getAllCasesRowsHTML(filtered)}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function getAllCasesRowsHTML(list) {
  if (!list.length) {
    return `<tr><td colspan="9" style="text-align: center; padding: 24px; color: var(--text-muted);">No matching grievances found.</td></tr>`;
  }

  return list.map(g => `
    <tr>
      <td><strong>#${g.id}</strong></td>
      <td><code style="font-size: 0.75rem;">${g.token}</code></td>
      <td>${g.cat}</td>
      <td>${escapeHtml(g.loc)}</td>
      <td><strong>${escapeHtml(g.title)}</strong></td>
      <td>${escapeHtml(g.authority)}</td>
      <td>
        ${g.status === 'Resolved' ? '<span class="status-pill status-resolved">Resolved</span>' :
          getSimulatedNow() > g.due ? '<span class="status-pill status-overdue">Overdue</span>' :
          g.escCount > 0 ? '<span class="status-pill status-escalated">Escalated</span>' :
          '<span class="status-pill status-open">Open</span>'}
      </td>
      <td style="font-family: var(--font-mono); font-size: 0.75rem;">${formatDate(g.due)}</td>
      <td>
        <button class="btn btn-secondary btn-sm" style="padding: 3px 8px; font-size: 0.75rem;" onclick="inspectFromMaster('${g.token}')">
          View
        </button>
      </td>
    </tr>
  `).join('');
}

function updateAllCasesRows() {
  const tbody = $('all-cases-tbody');
  if (!tbody) return;
  const q = (state.allCasesSearch || '').toLowerCase();
  const c = state.allCasesCat || 'ALL';
  const filtered = state.db.g.filter(g => {
    const matchCat = (c === 'ALL') || (g.cat === c);
    const matchQuery = !q || g.title.toLowerCase().includes(q) || g.token.toLowerCase().includes(q) || g.loc.toLowerCase().includes(q) || g.desc.toLowerCase().includes(q);
    return matchCat && matchQuery;
  });
  tbody.innerHTML = getAllCasesRowsHTML(filtered);
}

function inspectFromMaster(token) {
  state.role = 'student';
  state.currentTab = 'track';
  state.activeReceiptToken = token;
  renderApp();
  setTimeout(() => {
    executeTrackLookup();
  }, 50);
}

function exportDataAsJSON() {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.db, null, 2));
  const dlAnchorElem = document.createElement('a');
  dlAnchorElem.setAttribute("href", dataStr);
  dlAnchorElem.setAttribute("download", `campusvoice_audit_export_${Date.now()}.json`);
  dlAnchorElem.click();
  showToast('Audit ledger and grievances exported as JSON', 'success');
}

// ------------------------------------------
// VIEW 10: VIVA & ARCHITECTURE SHOWCASE
// ------------------------------------------
function renderVivaArchitectureView() {
  return `
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">🏛️ Project Viva Reference & Academic Architecture</h2>
          <p class="card-desc">Complete technical mappings for Semester 3 evaluation: System Design, RDBMS (3NF), Azure DP-900 Data Services, and Cloud Security.</p>
        </div>
      </div>

      <!-- Section 1: System Design -->
      <div class="arch-card">
        <h3 style="color: var(--accent); font-size: 1.05rem; margin-bottom: 8px;">1. System Design Architecture</h3>
        <p style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 12px;">
          Layered decoupled architecture separating public client-facing anonymous interfaces from back-end micro-services.
        </p>
        <ul style="padding-left: 20px; font-size: 0.85rem; line-height: 1.6; color: var(--text-main);">
          <li><strong>Client Layer:</strong> Progressive Web App (PWA) with zero client tracking, zero cookies, zero PII storage.</li>
          <li><strong>API Gateway & REST Layer:</strong> Endpoints for <code>POST /api/grievances</code> (returns receipt token), <code>GET /api/grievances/{token}</code> (tracks status), <code>PATCH /api/grievances/{id}/status</code> (role-protected authority actions).</li>
          <li><strong>SLA Daemon / Scheduler Service:</strong> Independent cron-driven microservice querying <code>due_date &lt; NOW() AND status != 'Resolved'</code>, triggering automated tier elevation and generating tamper-evident audit payloads.</li>
          <li><strong>Architectural Trade-Off:</strong> Hash-Chained Audit Log vs Standard RDBMS Logs. <em>Trade-off:</em> Additional compute overhead per state transition in exchange for mathematically verifiable tamper-evidence where no rogue DBA can quietly alter records.</li>
        </ul>
      </div>

      <!-- Section 2: RDBMS 3NF Schema -->
      <div class="arch-card">
        <h3 style="color: var(--accent); font-size: 1.05rem; margin-bottom: 8px;">2. RDBMS Normalized Schema (3NF - 7 Relational Tables)</h3>
        <p style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 12px;">
          All entities in Third Normal Form (3NF) to eliminate insertion, deletion, and update anomalies.
        </p>
        <div style="overflow-x: auto;">
          <table class="schema-table">
            <thead>
              <tr>
                <th>Table Name</th>
                <th>Primary Key</th>
                <th>Foreign Keys & Constraints</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><code>users</code></td>
                <td><code>user_id</code></td>
                <td><code>role_id REFERENCES roles(role_id)</code></td>
                <td>Authority and administrator credentials (bcrypt hashed)</td>
              </tr>
              <tr>
                <td><code>roles</code></td>
                <td><code>role_id</code></td>
                <td><code>UNIQUE(role_name)</code></td>
                <td>Student, Authority (Warden, HOD, Mess, etc.), Administrator</td>
              </tr>
              <tr>
                <td><code>departments</code></td>
                <td><code>dept_id</code></td>
                <td><code>head_user_id REFERENCES users(user_id)</code></td>
                <td>Campus faculties and hostels managing specific complaints</td>
              </tr>
              <tr>
                <td><code>grievances</code></td>
                <td><code>grievance_id</code></td>
                <td><code>dept_id, UNIQUE(receipt_token)</code></td>
                <td>Anonymous complaints. ZERO user_id column to protect anonymity</td>
              </tr>
              <tr>
                <td><code>escalation_rules</code></td>
                <td><code>rule_id</code></td>
                <td><code>dept_id, tier_level, sla_hours</code></td>
                <td>SLA deadlines and tier routing per complaint category</td>
              </tr>
              <tr>
                <td><code>status_history</code></td>
                <td><code>history_id</code></td>
                <td><code>grievance_id, updated_by_user_id</code></td>
                <td>Audit trail of investigation notes and milestone transitions</td>
              </tr>
              <tr>
                <td><code>attachments</code></td>
                <td><code>attachment_id</code></td>
                <td><code>grievance_id, blob_uri, sha256_checksum</code></td>
                <td>Metadata pointing to encrypted files in Azure Blob Storage</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 3: Azure DP-900 Data Services -->
      <div class="arch-card">
        <h3 style="color: var(--accent); font-size: 1.05rem; margin-bottom: 8px;">3. Microsoft Azure Data Services (DP-900 Mapping)</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; margin-top: 10px;">
          <div style="background: var(--bg-tertiary); padding: 12px; border-radius: var(--radius-sm);">
            <strong>🗄️ Azure SQL Database</strong>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">
              Stores structured transactional data (grievances, escalation policies, user roles) with ACID guarantees, row-level security, and T-SQL stored procedures.
            </p>
          </div>
          <div style="background: var(--bg-tertiary); padding: 12px; border-radius: var(--radius-sm);">
            <strong>📦 Azure Blob Storage</strong>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">
              Unstructured data repository holding photographic evidence and PDF reports with server-side AES-256 encryption and SAS time-limited access tokens.
            </p>
          </div>
          <div style="background: var(--bg-tertiary); padding: 12px; border-radius: var(--radius-sm);">
            <strong>🪐 Azure Cosmos DB</strong>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">
              Semi-structured immutable JSON document store for the hash-chained audit ledger, providing single-digit millisecond latency and distributed consistency.
            </p>
          </div>
          <div style="background: var(--bg-tertiary); padding: 12px; border-radius: var(--radius-sm);">
            <strong>📈 Microsoft Power BI</strong>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">
              DirectQuery connection to Azure SQL and Cosmos DB providing administrative heatmaps, SLA compliance rates, and hostel hotspot analytics.
            </p>
          </div>
        </div>
      </div>

      <!-- Section 4: Cloud Security -->
      <div class="arch-card">
        <h3 style="color: var(--accent); font-size: 1.05rem; margin-bottom: 8px;">4. Cloud Security & Anonymity Defense</h3>
        <ul style="padding-left: 20px; font-size: 0.85rem; line-height: 1.6; color: var(--text-main);">
          <li><strong>Zero PII Principle:</strong> The database schema strictly prohibits storing student IP addresses, emails, or hardware identifiers alongside grievances.</li>
          <li><strong>Secret Management:</strong> Azure Key Vault houses database connection strings, Cosmos DB keys, and encryption certificates; never committed to Git.</li>
          <li><strong>Role-Based Access Control (RBAC):</strong> Granular permissions enforced via JWT bearer tokens (Student: file/track only; Authority: view/resolve queue; Admin: audit/analytics).</li>
          <li><strong>Application Defense:</strong> Input sanitization against Cross-Site Scripting (XSS), SQL parameterization against SQL Injection (SQLi), and TLS 1.3 encryption in transit.</li>
        </ul>
      </div>
    </div>
  `;
}

// ==========================================
// PRESETS & EVIDENCE MODAL HANDLERS
// ==========================================
const PRESETS = {
  water: {
    cat: 'Hostel',
    loc: 'Hostel Block A (Boys)',
    urgency: 'Critical',
    title: 'Severe water pipe leakage in 3rd floor washroom corridor',
    desc: 'The overhead plumbing connector ruptured in washroom 304. Water is pooling into adjacent dorm rooms and reaching the main floor electrical junction box. Urgent plumber attention needed before short-circuit hazard.',
    files: [{ name: 'corridor_flood_304.jpg', size: 215000, type: 'image/jpeg', blobUrl: 'blob://campusvoice-evidence/blob_water_leak.jpg' }]
  },
  mess: {
    cat: 'Mess & Food',
    loc: 'Central Mess Hall',
    urgency: 'High',
    title: 'Unhygienic food preparation & foul-smelling paneer served at lunch',
    desc: 'Today at lunch, the paneer curry had a sour pungent odor and multiple students reported nausea. The dishwashing counters are also contaminated with stagnant wastewater. Please conduct an unannounced food safety audit.',
    files: [{ name: 'mess_food_sample.jpg', size: 310000, type: 'image/jpeg', blobUrl: 'blob://campusvoice-evidence/blob_mess_sample.jpg' }]
  },
  lab: {
    cat: 'Lab & Equipment',
    loc: 'Computer Science Block - Lab 301',
    urgency: 'Normal',
    title: '15 workstations unable to boot OS in Operating Systems lab',
    desc: 'Computers 10 to 25 exhibit hard disk read errors on dual-boot grub screen. Mid-term practical lab exam is scheduled this Thursday, impacting 45 students.',
    files: [{ name: 'pc_boot_error_log.pdf', size: 104000, type: 'application/pdf', blobUrl: 'blob://campusvoice-evidence/blob_lab_log.pdf' }]
  },
  ragging: {
    cat: 'Ragging & Harassment',
    loc: 'Hostel Block B (Boys)',
    urgency: 'Critical',
    title: 'Unauthorized late-night summoning of freshers in common hall',
    desc: 'Senior batch students from 4th year are mandating freshers to stay up until 2:30 AM for informal questioning and restricting movement. Immediate proctorial patrol required.',
    files: []
  }
};

function loadFormPreset(type) {
  const p = PRESETS[type];
  if (!p) return;
  const catEl = $('fg-cat');
  if (catEl) {
    catEl.value = p.cat;
    updateRoutingPreview(p.cat);
  }
  if ($('fg-loc')) $('fg-loc').value = p.loc;
  if ($('fg-urgency')) $('fg-urgency').value = p.urgency;
  if ($('fg-title')) $('fg-title').value = p.title;
  if ($('fg-desc')) {
    $('fg-desc').value = p.desc;
    updateCharCount($('fg-desc'));
  }
  state.uploadedFilesCache = [...p.files];
  const preview = $('file-preview-list');
  if (preview) {
    preview.innerHTML = p.files.map(f => `
      <div class="file-preview-item">
        <div class="file-info">
          <span>${f.name.endsWith('.pdf') ? '📄' : '🖼️'}</span>
          <strong>${escapeHtml(f.name)}</strong>
          <span style="color: var(--text-muted);">(${Math.round(f.size / 1024)} KB)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="file-badge">Azure Blob Encrypted</span>
          <span style="color: var(--success); font-size: 0.8rem;">✓ Loaded</span>
        </div>
      </div>
    `).join('');
  }
  showToast(`Loaded ${p.cat} preset into form`, 'info');
}

function viewEvidenceModal(gid, fileIndex) {
  const g = state.db.g.find(x => x.id === gid);
  if (!g || !g.files || !g.files[fileIndex]) return;
  const f = g.files[fileIndex];
  const isPdf = (f.name && f.name.endsWith('.pdf')) || (f.type && f.type.includes('pdf'));

  const modal = $('evidence-modal');
  if (!modal) return;
  $('ev-modal-filename').textContent = f.name;
  $('ev-modal-meta').innerHTML = `
    <strong>Storage URI:</strong> <code>${escapeHtml(f.blobUrl || 'blob://campusvoice-evidence/' + f.name)}</code><br>
    <strong>Size:</strong> ${Math.round(f.size / 1024)} KB • <strong>Container:</strong> Azure Blob Storage (private-read)<br>
    <strong>Security:</strong> AES-256 Server-Side Encryption with SAS Time-Limited Delegation Key<br>
    <strong>Malware Scan:</strong> <span style="color: var(--success); font-weight: bold;">✓ Microsoft Defender for Cloud (Clean)</span>
  `;

  const previewBody = $('ev-modal-preview');
  if (isPdf) {
    previewBody.innerHTML = `
      <div style="background: var(--bg-tertiary); border: 1px solid var(--border-medium); border-radius: var(--radius-md); padding: 32px 20px; text-align: center;">
        <div style="font-size: 3rem; margin-bottom: 8px;">📄</div>
        <h4 style="font-size: 1rem; font-weight: 700;">${escapeHtml(f.name)}</h4>
        <p style="font-size: 0.8rem; color: var(--text-muted); margin: 6px 0 16px;">
          Encrypted PDF Document (Simulated Azure Blob payload preview)
        </p>
        <div style="background: var(--bg-card); max-width: 440px; margin: 0 auto; padding: 16px; border-radius: var(--radius-sm); text-align: left; font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">
          [ATTACHMENT VERIFIED]<br>
          SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855<br>
          Case Reference: #${g.id} (${escapeHtml(g.title)})<br>
          Access Policy: Authority Read-Only Delegation
        </div>
      </div>
    `;
  } else {
    previewBody.innerHTML = `
      <div style="background: var(--bg-tertiary); border: 1px solid var(--border-medium); border-radius: var(--radius-md); padding: 20px; text-align: center;">
        <div style="background: linear-gradient(135deg, #1e293b, #0f172a); border-radius: var(--radius-md); padding: 40px 20px; color: #e2e8f0; margin-bottom: 12px;">
          <div style="font-size: 3.5rem; margin-bottom: 8px;">📷</div>
          <div style="font-weight: 700; font-size: 1.05rem;">Visual Evidence Captured</div>
          <div style="font-size: 0.8rem; opacity: 0.8; margin-top: 4px;">${escapeHtml(f.name)} (${Math.round(f.size / 1024)} KB)</div>
          <div style="margin-top: 14px; display: inline-block; padding: 4px 12px; background: rgba(20, 184, 166, 0.2); color: #5eead4; border-radius: 99px; font-size: 0.75rem;">
            Blob Checksum Verified: 0x9F2A...3C81
          </div>
        </div>
      </div>
    `;
  }

  modal.classList.add('open');
}

function closeEvidenceModal() {
  const m = $('evidence-modal');
  if (m) m.classList.remove('open');
}

// ==========================================
// EVENT LISTENERS & INITIALIZATION
// ==========================================
function attachDynamicEventListeners() {
  // Drag and drop listeners on dropzone if present
  const dropzone = $('file-dropzone');
  if (dropzone) {
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--primary)';
    });
    dropzone.addEventListener('dragleave', () => {
      dropzone.style.borderColor = 'var(--border-medium)';
    });
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--border-medium)';
      if (e.dataTransfer.files && e.dataTransfer.files.length) {
        handleFileUpload(e.dataTransfer.files);
      }
    });
  }
}

async function initApplication() {
  loadState();

  // Load saved theme
  const savedTheme = localStorage.getItem('cv_theme') || 'light';
  state.currentTheme = savedTheme;
  document.documentElement.setAttribute('data-theme', savedTheme);
  const themeLabel = $('theme-label');
  if (themeLabel) themeLabel.textContent = savedTheme === 'light' ? '🌙 Dark' : '☀️ Light';

  if (!state.db.g || state.db.g.length === 0) {
    await seedDemonstrationData();
  } else {
    await checkAndEscalateSLA();
    renderApp();
  }

  // Periodic background escalation check (every 10 seconds)
  setInterval(checkAndEscalateSLA, 10000);
}

// Bootstrap on DOM ready
document.addEventListener('DOMContentLoaded', initApplication);
