/**
 * PhishGuard — Phishing Attack Investigation Platform (PS-02)
 * Production Frontend Application Bundle
 * 
 * Strict Invariants:
 * 1. ZERO hardcoded mock scores in templates.
 * 2. ZERO fake component risk percentages (sender %, domain %, etc.).
 * 3. Domain Analysis is FULLY dynamic (no hardcoded PayPal or domains).
 * 4. Dedicated SPA hash routing with distinct sub-pages and back navigation (no accordions).
 * 5. Real API integration: POST https://phishguard-1-m1se.onrender.com/api/analyze
 */

'use strict';

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================
//const API_BASE = 'https://phishguard-1-m1se.onrender.com';
const API_BASE = 'https://phishguard-1-m1se.onrender.com';
const STORAGE_KEY = 'phishguard_analysis_v2';
const AUTH_KEY = 'phishguard_analyst_session';

const ROUTES = {
  '#/login': 'view-login',
  '#/dashboard': 'view-dashboard',
  '#/investigate': 'view-investigate',
  '#/results': 'view-results',
  '#/results/threat-analysis': 'view-detail-threat',
  '#/results/domain': 'view-detail-domain',
  '#/results/url': 'view-detail-url',
  '#/results/evidence': 'view-detail-evidence',
  '#/results/indicators': 'view-detail-indicators',
  '#/results/recommended-action': 'view-detail-action',
  '#/report': 'view-report'
};

// Global in-memory active investigation state
let currentAnalysis = null;

// ============================================================================
// HELPER UTILITIES
// ============================================================================
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `cyber-toast ${type}`;
  
  let icon = 'ℹ';
  if (type === 'success') icon = '✔';
  if (type === 'error') icon = '✖';
  if (type === 'warning') icon = '⚠';

  toast.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <span class="toast-text">${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 4000);
}

function copyToClipboard(text, successMsg = 'Copied to clipboard!') {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(successMsg, 'success');
    }).catch(() => {
      fallbackCopy(text, successMsg);
    });
  } else {
    fallbackCopy(text, successMsg);
  }
}

function fallbackCopy(text, successMsg) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.left = '-9999px';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
    showToast(successMsg, 'success');
  } catch (err) {
    showToast('Failed to copy to clipboard', 'error');
  }
  document.body.removeChild(textArea);
}

function extractDomain(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch (e) {
    return url.replace(/^https?:\/\//i, '').split('/')[0].split('?')[0];
  }
}

// ============================================================================
// ROUTING ENGINE (SPA HASH ROUTER)
// ============================================================================
function navigateTo(hash) {
  window.location.hash = hash;
}

function handleRouteChange() {
  let hash = window.location.hash || '#/dashboard';

  // Normalize empty or root
  if (hash === '#' || hash === '' || hash === '#/') {
    hash = '#/dashboard';
  }

  // Check route validity
  const targetViewId = ROUTES[hash];
  if (!targetViewId) {
    console.warn(`Unknown route: ${hash}, redirecting to dashboard.`);
    navigateTo('#/dashboard');
    return;
  }

  // Guard results and report routes: must have active analysis data
  const isResultsOrReport = hash.startsWith('#/results') || hash === '#/report';
  if (isResultsOrReport) {
    if (!currentAnalysis) {
      // Try restoring from sessionStorage
      const saved = sessionStorage.getItem(STORAGE_KEY);
      if (saved) {
        try {
          currentAnalysis = JSON.parse(saved);
          renderAllViews(currentAnalysis);
        } catch (e) {
          sessionStorage.removeItem(STORAGE_KEY);
        }
      }
    }

    if (!currentAnalysis) {
      showToast('No active investigation data found. Please run an analysis first.', 'warning');
      navigateTo('#/investigate');
      return;
    }
  }

  // Toggle View Containers
  document.querySelectorAll('.spa-view').forEach(view => {
    if (view.id === targetViewId) {
      view.classList.remove('hidden');
    } else {
      view.classList.add('hidden');
    }
  });

  // Scroll to top of window on view transition
  window.scrollTo({ top: 0, behavior: 'smooth' });

  // Update Navbar Active State
  updateNavbarState(hash);
}

function updateNavbarState(hash) {
  const dashLink = document.getElementById('navLinkDashboard');
  const invLink = document.getElementById('navLinkInvestigate');
  const resLink = document.getElementById('navLinkResults');
  const repLink = document.getElementById('navLinkReport');

  [dashLink, invLink, resLink, repLink].forEach(link => {
    if (link) link.classList.remove('active');
  });

  if (hash === '#/dashboard' && dashLink) dashLink.classList.add('active');
  if (hash === '#/investigate' && invLink) invLink.classList.add('active');
  if (hash.startsWith('#/results') && resLink) resLink.classList.add('active');
  if (hash === '#/report' && repLink) repLink.classList.add('active');

  // Show or hide Results & Report navbar tabs based on active investigation
  const hasData = Boolean(currentAnalysis);
  if (resLink) resLink.classList.toggle('hidden', !hasData);
  if (repLink) repLink.classList.toggle('hidden', !hasData);
}

// ============================================================================
// BACKEND CONNECTIVITY MONITOR
// ============================================================================
async function checkBackendHealth() {
  const statusPulse = document.getElementById('statusPulseDot');
  const statusText = document.getElementById('statusText');
  const dashStatus = document.getElementById('dashBackendStatus');

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`${API_BASE}/api/health`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (res.ok) {
      if (statusPulse) statusPulse.className = 'status-pulse-dot online';
      if (statusText) {
        statusText.textContent = 'API: ONLINE (FASTAPI)';
        statusText.classList.remove('text-red');
        statusText.classList.add('text-green');
      }
      if (dashStatus) {
        dashStatus.textContent = 'https://phishguard-1-m1se.onrender.com (Active)';
        dashStatus.className = 'metric-val text-green font-mono';
      }
      return true;
    }
  } catch (err) {
    // API offline or unreachable
  }

  if (statusPulse) statusPulse.className = 'status-pulse-dot offline';
  if (statusText) {
    statusText.textContent = 'API: OFFLINE (PORT 8000)';
    statusText.classList.remove('text-green');
    statusText.classList.add('text-red');
  }
  if (dashStatus) {
    dashStatus.textContent = 'https://phishguard-1-m1se.onrender.com (Offline — Start FastAPI)';
    dashStatus.className = 'metric-val text-red font-mono';
  }
  return false;
}

// ============================================================================
// THREAT ANALYSIS DISPATCHER
// ============================================================================
async function handleInvestigationSubmit(e) {
  e.preventDefault();

  const senderInput = document.getElementById('senderInput');
  const subjectInput = document.getElementById('subjectInput');
  const urlInput = document.getElementById('urlInput');
  const bodyInput = document.getElementById('emailBodyInput');
  const errorAlert = document.getElementById('formErrorAlert');
  const errorMessage = document.getElementById('formErrorMessage');
  const submitBtn = document.getElementById('analyzeSubmitBtn');
  const overlay = document.getElementById('loadingOverlay');

  const sender = (senderInput?.value || '').trim();
  const subject = (subjectInput?.value || '').trim();
  const url = (urlInput?.value || '').trim();
  const body = (bodyInput?.value || '').trim();

  // Validation: At least one field required
  if (!sender && !subject && !url && !body) {
    if (errorAlert && errorMessage) {
      errorMessage.textContent = 'Please enter at least one field (sender email, subject, URL, or body) for heuristic analysis.';
      errorAlert.classList.remove('hidden');
    }
    showToast('Please provide at least one input field to analyze.', 'error');
    return;
  }

  if (errorAlert) errorAlert.classList.add('hidden');
  if (submitBtn) submitBtn.disabled = true;
  if (overlay) overlay.classList.remove('hidden');

  // Trigger telemetry visual steps
  animateLoadingSteps();

  try {
    const payload = { sender, subject, body, url };
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      let detailMsg = `Analysis request failed with HTTP ${res.status}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) detailMsg = errJson.detail;
      } catch (_) {}
      throw new Error(detailMsg);
    }

    const data = await res.json();
    console.log("BACKEND RISK SCORE:", data.risk_score);
    console.log("FULL BACKEND DATA:", data);

    // Enrich with operational investigation metadata
    data.timestamp = new Date().toLocaleString();
    data.caseId = 'PG-' + Math.floor(100000 + Math.random() * 900000);
    data.rawInputs = { sender, subject, url, body };

    // Update state and persistence
    currentAnalysis = data;
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(data));

    // Render all sub-pages with genuine returned backend data
    renderAllViews(data);

    // Conclude loading transition
    setTimeout(() => {
      if (overlay) overlay.classList.add('hidden');
      if (submitBtn) submitBtn.disabled = false;
      navigateTo('#/results');
      showToast(`Analysis completed: ${data.verdict} Risk (Score: ${data.risk_score}/100)`, 'success');
    }, 850);

  } catch (err) {
    console.error('API Error:', err);
    if (overlay) overlay.classList.add('hidden');
    if (submitBtn) submitBtn.disabled = false;

    if (errorAlert && errorMessage) {
      //errorMessage.textContent = `Backend Analysis Error: ${err.message}. Verify that the PhishGuard API is reachable at https://phishguard-1-m1se.onrender.com;
      errorMessage.textContent = `Backend Analysis Error: ${err.message}. Verify that the PhishGuard API is reachable at https://phishguard-1-m1se.onrender.com`;
      errorAlert.classList.remove('hidden');
    }
    showToast(`Analysis failed: ${err.message}`, 'error');
  }
}

function animateLoadingSteps() {
  const fill = document.getElementById('loadingBarFill');
  const s1 = document.getElementById('lStep1');
  const s2 = document.getElementById('lStep2');
  const s3 = document.getElementById('lStep3');

  if (fill) fill.style.width = '15%';
  [s1, s2, s3].forEach(el => el && (el.style.opacity = '0.4'));

  if (s1) s1.style.opacity = '1';

  setTimeout(() => {
    if (fill) fill.style.width = '55%';
    if (s2) s2.style.opacity = '1';
  }, 300);

  setTimeout(() => {
    if (fill) fill.style.width = '90%';
    if (s3) s3.style.opacity = '1';
  }, 600);
}

// ============================================================================
// COMPREHENSIVE VIEW RENDERERS (NO HARDCODING, NO FAKE PERCENTAGES)
// ============================================================================
function renderAllViews(data) {
  if (!data) return;

  renderResultsOverview(data);
  renderThreatAnalysisView(data);
  renderDomainView(data);
  renderUrlView(data);
  renderEvidenceView(data);
  renderIndicatorsView(data);
  renderActionView(data);
  renderReportView(data);

  // Update navigation items visibility
  const resLink = document.getElementById('navLinkResults');
  const repLink = document.getElementById('navLinkReport');
  if (resLink) resLink.classList.remove('hidden');
  if (repLink) repLink.classList.remove('hidden');
}

/**
 * 1. Result Overview Page (#/results)
 */
function renderResultsOverview(data) {
  const scoreEl = document.getElementById('resultsRiskScore');
  const badgeEl = document.getElementById('resultsVerdictBadge');
  const headlineEl = document.getElementById('resultsVerdictHeadline');
  const summaryEl = document.getElementById('resultsHumanSummary');
  const meterFill = document.getElementById('resultsMeterFill');
  const caseIdEl = document.getElementById('resultsCaseId');

  const score = typeof data.risk_score === 'number' ? data.risk_score : 0;
  const verdict = (data.verdict || 'UNKNOWN').toUpperCase();

  // 1. Score display
  if (scoreEl) scoreEl.textContent = score;
  
  if (caseIdEl) caseIdEl.textContent = `CASE: ${data.caseId || '--'}`;

  // 2. Circular meter animation
  if (meterFill) {
    const circumference = 427.26; // 2 * PI * 68
    const offset = circumference - (circumference * Math.min(Math.max(score, 0), 100)) / 100;
    meterFill.style.strokeDashoffset = offset;

    // Meter color dynamically styled based on score
    if (score >= 70) {
      meterFill.style.stroke = '#ff3366';
    } else if (score >= 40) {
      meterFill.style.stroke = '#ffaa00';
    } else {
      meterFill.style.stroke = '#00ff88';
    }
  }

  // 3. Verdict badge & headline
  if (badgeEl) {
    badgeEl.textContent = verdict;
    badgeEl.className = 'verdict-badge';
    if (verdict === 'HIGH' || score >= 70) {
      badgeEl.classList.add('badge-high');
    } else if (verdict === 'MEDIUM' || score >= 40) {
      badgeEl.classList.add('badge-medium');
    } else {
      badgeEl.classList.add('badge-low');
    }
  }

  if (headlineEl) {
    if (score >= 70 || verdict === 'HIGH') {
      headlineEl.textContent = 'HIGH RISK PHISHING THREAT DETECTED';
      headlineEl.style.color = '#ff3366';
    } else if (score >= 40 || verdict === 'MEDIUM') {
      headlineEl.textContent = 'SUSPICIOUS MESSAGE — PROCEED WITH CAUTION';
      headlineEl.style.color = '#ffaa00';
    } else {
      headlineEl.textContent = 'LOW RISK — NO PROVEN ANOMALIES';
      headlineEl.style.color = '#00ff88';
    }
  }

  // 4. "Why is this suspicious?" dynamic human-readable explanation
  if (summaryEl) {
    summaryEl.textContent = buildDynamicWhySuspiciousText(data);
  }
}

function buildDynamicWhySuspiciousText(data) {
  const parts = [];
  const score = data.risk_score || 0;
  const verdict = data.verdict || 'UNKNOWN';

  parts.push(`This message received an overall threat index of ${score}/100 (${verdict} Risk).`);

  if (data.domain_similarity && data.matched_brand) {
    parts.push(`Critical Brand Impersonation: The sender domain targets '${data.matched_brand}' via ${data.similarity_reason || 'lookalike domain syntax'}.`);
  } else if (data.domain_similarity) {
    parts.push(`Typosquatting Detected: ${data.similarity_reason || 'Deceptive domain syntax detected'}.`);
  }

  const indicators = data.indicators || [];
  if (indicators.length > 0) {
    const indicatorNames = indicators.map(ind => typeof ind === 'string' ? ind : (ind.name || ind.id || 'Trigger')).slice(0, 3);
    parts.push(`Triggered heuristic indicators include: ${indicatorNames.join(', ')}.`);
  }

  if (score < 40 && indicators.length === 0 && !data.domain_similarity) {
    return `This communication scored ${score}/100 (${verdict} Risk). The security engine found no signs of brand impersonation, deceptive homoglyph characters, or high-urgency social engineering patterns.`;
  }

  return parts.join(' ');
}

/**
 * 2. Dedicated Threat Analysis Page (#/results/threat-analysis)
 * NOTE: User Correction 1 — ZERO fake component percentages!
 */
function renderThreatAnalysisView(data) {
  const summaryText = document.getElementById('threatAnalysisSummaryText');
  const scoreDisplay = document.getElementById('threatScoreDisplay');
  const verdictDisplay = document.getElementById('threatVerdictDisplay');
  const verdictCaption = document.getElementById('threatVerdictCaption');
  const componentGrid = document.getElementById('componentStatusGrid');

  const score = data.risk_score || 0;
  const verdict = data.verdict || 'UNKNOWN';

  if (scoreDisplay) scoreDisplay.textContent = score;
  if (verdictDisplay) {
    verdictDisplay.textContent = verdict;
    if (score >= 70) verdictDisplay.className = 'verdict-text text-red';
    else if (score >= 40) verdictDisplay.className = 'verdict-text text-orange';
    else verdictDisplay.className = 'verdict-text text-green';
  }

  if (summaryText) {
    summaryText.textContent = `The evaluated threat score (${score}/100) was synthesized by the FastAPI heuristic engine based on real pattern violations detected across headers, domains, and text structure.`;
  }

  if (verdictCaption) {
    if (score >= 70) {
      verdictCaption.textContent = 'High confidence malicious phishing attack signature.';
    } else if (score >= 40) {
      verdictCaption.textContent = 'Moderate suspicion level. Manual verification advised.';
    } else {
      verdictCaption.textContent = 'Standard heuristic thresholds passed. Low threat potential.';
    }
  }

  // Component Checklist: strictly boolean/qualitative flags from genuine backend findings
  if (componentGrid) {
    const raw = data.rawInputs || {};
    const indicators = data.indicators || [];
    const evidence = data.evidence || [];

    // Evaluate each component based on real data
    const hasDomainSim = Boolean(data.domain_similarity);
    const hasSenderFlag = Boolean(data.domain_analysis?.has_suspicious_tld) || hasDomainSim || indicators.some(i => (typeof i === 'string' ? i : i.name || '').toLowerCase().includes('sender') || (typeof i === 'string' ? i : i.name || '').toLowerCase().includes('domain'));
    const hasUrlFlag = Boolean(data.url_analysis?.has_ip) || indicators.some(i => (typeof i === 'string' ? i : i.name || '').toLowerCase().includes('url') || (typeof i === 'string' ? i : i.name || '').toLowerCase().includes('http'));
    const hasUrgencyFlag = indicators.some(i => (typeof i === 'string' ? i : i.name || '').toLowerCase().includes('urgent') || (typeof i === 'string' ? i : i.name || '').toLowerCase().includes('suspension') || (typeof i === 'string' ? i : i.name || '').toLowerCase().includes('credential'));

    const components = [
      {
        title: 'Brand Impersonation & Typosquatting',
        status: hasDomainSim ? 'FLAGGED' : 'PASSED',
        isDanger: hasDomainSim,
        detail: hasDomainSim 
          ? `Deceptive lookalike detected targeting '${escapeHtml(data.matched_brand || 'monitored brand')}' (${escapeHtml(data.similarity_reason || '')}).`
          : 'No lookalike signatures or homoglyph character substitutions detected.'
      },
      {
        title: 'Sender Domain & Header Syntax',
        status: hasSenderFlag ? 'FLAGGED' : 'PASSED',
        isDanger: hasSenderFlag,
        detail: hasSenderFlag 
          ? `Sender domain '${escapeHtml(data.domain_analysis?.sender_domain || raw.sender || 'unknown')}' triggered defensive domain heuristics.`
          : `Sender domain '${escapeHtml(data.domain_analysis?.sender_domain || raw.sender || 'unknown')}' matches standard DNS/naming conventions.`
      },
      {
        title: 'URL & Destination Security',
        status: raw.url ? (hasUrlFlag ? 'FLAGGED' : 'PASSED') : 'NOT PROVIDED',
        isDanger: hasUrlFlag,
        detail: raw.url
          ? (hasUrlFlag ? 'Hyperlink uses insecure transfer protocol or suspicious domain routing.' : 'Hyperlink destination has standard structure without immediate flags.')
          : 'No external URL target was provided in this investigation case.'
      },
      {
        title: 'Urgency & Coercive Language',
        status: hasUrgencyFlag ? 'FLAGGED' : 'PASSED',
        isDanger: hasUrgencyFlag,
        detail: hasUrgencyFlag
          ? 'Language exhibits artificial panic, immediate suspension threats, or credential demand cues.'
          : 'No urgent pressure cues or aggressive security intimidation detected.'
      }
    ];

    componentGrid.innerHTML = components.map(c => `
      <div class="comp-status-card ${c.isDanger ? 'border-danger' : 'border-safe'}">
        <div class="comp-head-row">
          <span class="comp-title-text">${c.title}</span>
          <span class="comp-badge-pill ${c.isDanger ? 'pill-danger' : (c.status === 'PASSED' ? 'pill-safe' : 'pill-neutral')}">${c.status}</span>
        </div>
        <p class="comp-detail-desc">${c.detail}</p>
      </div>
    `).join('');
  }
}

/**
 * 3. Dedicated Domain & Brand Forensics Page (#/results/domain)
 * NOTE: User Correction 2 — FULLY dynamic! No hardcoded PayPal or domains.
 */
function renderDomainView(data) {
  const explanationEl = document.getElementById('domainExplanationText');
  const badgeEl = document.getElementById('domainOverallBadge');
  const senderEl = document.getElementById('domainDetailSender');
  const simFlagEl = document.getElementById('domainDetailSimFlag');
  const brandEl = document.getElementById('domainDetailBrand');
  const reasonEl = document.getElementById('domainDetailReason');
  const comparisonBlock = document.getElementById('domainComparisonBlock');

  const senderDomain = data.domain_analysis?.sender_domain || (data.rawInputs?.sender ? data.rawInputs.sender.split('@')[1] : null) || 'Not provided';
  const hasSimilarity = Boolean(data.domain_similarity);
  const matchedBrand = data.matched_brand || null;
  const similarityReason = data.similarity_reason || (hasSimilarity ? 'Suspicious similarity pattern' : 'No deceptive patterns detected');

  if (senderEl) senderEl.textContent = senderDomain;
  if (brandEl) brandEl.textContent = matchedBrand || 'None (No brand targeted)';
  if (reasonEl) reasonEl.textContent = similarityReason;

  if (badgeEl) {
    if (hasSimilarity) {
      badgeEl.textContent = 'DECEPTIVE LOOKALIKE';
      badgeEl.className = 'badge-status badge-danger';
    } else {
      badgeEl.textContent = 'AUTHENTIC / UNMATCHED';
      badgeEl.className = 'badge-status badge-safe';
    }
  }

  if (simFlagEl) {
    if (hasSimilarity) {
      simFlagEl.textContent = 'YES — LOOKALIKE DETECTED';
      simFlagEl.className = 'prop-val font-mono text-red';
    } else {
      simFlagEl.textContent = 'NO — NO BRAND MISMATCH';
      simFlagEl.className = 'prop-val font-mono text-green';
    }
  }

  // Dynamic explanation text
  if (explanationEl) {
    if (hasSimilarity && matchedBrand) {
      explanationEl.textContent = `The sender domain '${senderDomain}' was detected mimicking the legitimate brand '${matchedBrand}'. Identified mechanism: ${similarityReason}. Threat actors use this technique to deceive recipients into entering credentials or bypassing routine vigilance.`;
    } else if (hasSimilarity) {
      explanationEl.textContent = `The sender domain '${senderDomain}' was flagged for suspicious lookalike syntax: ${similarityReason}.`;
    } else {
      explanationEl.textContent = `The sender domain '${senderDomain}' does not match any monitored high-value brand lookalike patterns or deceptive homoglyph substitutions.`;
    }
  }

  // Dynamic side-by-side comparison block
  if (comparisonBlock) {
    if (hasSimilarity && matchedBrand) {
      comparisonBlock.innerHTML = `
        <div class="dynamic-homoglyph-comparison">
          <div class="homoglyph-card authentic-side">
            <span class="homoglyph-label font-mono">GENUINE BRAND ENTITY</span>
            <div class="homoglyph-domain font-mono text-cyan">${escapeHtml(matchedBrand)}</div>
            <div class="homoglyph-sub font-mono">Authorized Official Domain Pattern</div>
          </div>
          <div class="homoglyph-vs font-mono">VS</div>
          <div class="homoglyph-card deceptive-side">
            <span class="homoglyph-label font-mono">SUBMITTED SENDER DOMAIN</span>
            <div class="homoglyph-domain font-mono text-red">${escapeHtml(senderDomain)}</div>
            <div class="homoglyph-sub font-mono text-orange">Detection: ${escapeHtml(similarityReason)}</div>
          </div>
        </div>
      `;
    } else {
      comparisonBlock.innerHTML = `
        <div class="dynamic-homoglyph-comparison clean">
          <div class="clean-box font-mono">
            <span class="text-green">✔ No typosquatting or homoglyph impersonation detected for domain: <strong>${escapeHtml(senderDomain)}</strong></span>
          </div>
        </div>
      `;
    }
  }
}

/**
 * 4. Dedicated URL Forensics Page (#/results/url)
 */
function renderUrlView(data) {
  const explanationEl = document.getElementById('urlExplanationText');
  const badgeEl = document.getElementById('urlStatusBadge');
  const displayAddress = document.getElementById('urlDisplayAddress');
  const protocolEl = document.getElementById('urlDetailProtocol');
  const hostEl = document.getElementById('urlDetailHost');
  const tlsEl = document.getElementById('urlDetailTls');
  const verdictEl = document.getElementById('urlDetailVerdict');
  const copyBtn = document.getElementById('copyUrlDetailBtn');

  const rawUrl = data.rawInputs?.url || '';
  const urlAnalysis = data.url_analysis || {};

  if (displayAddress) {
    displayAddress.textContent = rawUrl || 'No URL submitted in this case';
  }

  if (copyBtn) {
    copyBtn.onclick = () => {
      if (rawUrl) copyToClipboard(rawUrl, 'URL copied to clipboard!');
      else showToast('No URL available to copy.', 'warning');
    };
  }

  if (!rawUrl) {
    if (badgeEl) {
      badgeEl.textContent = 'NOT PROVIDED';
      badgeEl.className = 'badge-status badge-neutral';
    }
    if (protocolEl) protocolEl.textContent = 'N/A';
    if (hostEl) hostEl.textContent = 'N/A';
    if (tlsEl) tlsEl.textContent = 'N/A';
    if (verdictEl) verdictEl.textContent = 'NO LINK TARGET ANALYZED';
    if (explanationEl) {
      explanationEl.textContent = 'No hyperlink was submitted for this case. URL security heuristics were bypassed.';
    }
    return;
  }

  const isHttps = rawUrl.toLowerCase().startsWith('https://') || Boolean(urlAnalysis.is_https);
  const host = urlAnalysis.extracted_domain || extractDomain(rawUrl);
  const isSuspicious = !isHttps || Boolean(urlAnalysis.has_ip) || Boolean(urlAnalysis.has_suspicious_keywords);

  if (protocolEl) protocolEl.textContent = isHttps ? 'HTTPS' : 'HTTP (Insecure)';
  if (hostEl) hostEl.textContent = host || 'Unknown Host';
  if (tlsEl) {
    tlsEl.textContent = isHttps ? 'TLS / SSL Encrypted' : 'Cleartext (Unencrypted)';
    tlsEl.className = isHttps ? 'prop-val font-mono text-green' : 'prop-val font-mono text-red';
  }

  if (verdictEl) {
    verdictEl.textContent = isSuspicious ? 'POTENTIALLY SUSPICIOUS / INSECURE' : 'STANDARD HYPERLINK SYNTAX';
    verdictEl.className = isSuspicious ? 'prop-val font-mono text-orange' : 'prop-val font-mono text-green';
  }

  if (badgeEl) {
    badgeEl.textContent = isSuspicious ? 'SUSPICIOUS' : 'STANDARD';
    badgeEl.className = isSuspicious ? 'badge-status badge-danger' : 'badge-status badge-safe';
  }

  if (explanationEl) {
    if (!isHttps) {
      explanationEl.textContent = `The destination '${rawUrl}' uses cleartext HTTP instead of secure HTTPS, exposing traffic to interception. This is a common characteristic of cheap or quick credential-harvesting phishing kits.`;
    } else {
      explanationEl.textContent = `The link points to '${host}'. While it uses encrypted HTTPS transport, always verify the domain identity independently before supplying credentials.`;
    }
  }
}

/**
 * 5. Dedicated Forensic Evidence Page (#/results/evidence)
 */
function renderEvidenceView(data) {
  const container = document.getElementById('evidenceListContainer');
  if (!container) return;

  const evidence = data.evidence || [];

  if (evidence.length === 0) {
    container.innerHTML = `
      <div class="empty-state-card glass-card">
        <span class="empty-icon text-cyan">ℹ</span>
        <h4>No Direct Forensic Artifacts Flagged</h4>
        <p>The heuristic analyzer did not isolate explicit suspicious snippets or keywords from this message.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = evidence.map((item, idx) => {
    const itemNum = String(idx + 1).padStart(2, '0');
    return `
      <div class="evidence-artifact-card glass-card">
        <div class="artifact-top-row">
          <div class="artifact-badge font-mono">ARTIFACT #${itemNum}</div>
          <button class="btn-copy-sm" onclick="copyToClipboard('${escapeHtml(item).replace(/'/g, "\\'")}', 'Artifact #${itemNum} copied!')">
            Copy Snippet
          </button>
        </div>
        <div class="artifact-body font-mono">
          <code>${escapeHtml(item)}</code>
        </div>
      </div>
    `;
  }).join('');
}

/**
 * 6. Dedicated Threat Indicators Page (#/results/indicators)
 */
function renderIndicatorsView(data) {
  const grid = document.getElementById('indicatorsDetailGrid');
  if (!grid) return;

  const indicators = data.indicators || [];

  if (indicators.length === 0) {
    grid.innerHTML = `
      <div class="empty-state-card glass-card" style="grid-column: 1 / -1;">
        <span class="empty-icon text-green">✔</span>
        <h4>No Threat Indicators Triggered</h4>
        <p>Zero defined phishing attack signatures or heuristic rules were matched.</p>
      </div>
    `;
    return;
  }

  grid.innerHTML = indicators.map((ind, idx) => {
    let name = '';
    let desc = '';
    let severity = 'MEDIUM';

    if (typeof ind === 'string') {
      name = ind;
      desc = `Triggered security rule signature #${idx + 1}`;
    } else {
      name = ind.name || ind.id || `Rule #${idx + 1}`;
      desc = ind.description || ind.reason || '';
      if (ind.severity) severity = ind.severity.toUpperCase();
    }

    let pillClass = 'pill-warning';
    if (severity === 'HIGH' || severity === 'CRITICAL') pillClass = 'pill-danger';
    if (severity === 'LOW') pillClass = 'pill-safe';

    return `
      <div class="indicator-detail-card glass-card">
        <div class="indicator-card-head">
          <span class="indicator-sev-pill ${pillClass} font-mono">${escapeHtml(severity)}</span>
          <span class="indicator-index font-mono">#${String(idx + 1).padStart(2, '0')}</span>
        </div>
        <h4 class="indicator-title">${escapeHtml(name)}</h4>
        <p class="indicator-desc">${escapeHtml(desc || 'Heuristic threat signature detected by defensive analyzer.')}</p>
      </div>
    `;
  }).join('');
}

/**
 * 7. Dedicated Recommended Action Page (#/results/recommended-action)
 */
function renderActionView(data) {
  const titleEl = document.getElementById('actionDirectiveTitle');
  const textEl = document.getElementById('actionDirectiveText');

  const verdict = data.verdict || 'UNKNOWN';
  const actionText = data.recommended_action || 'Follow company cybersecurity policy and verify sender through known legitimate channels.';

  if (titleEl) {
    titleEl.textContent = `${verdict} Risk Mitigation Directive`;
  }
  if (textEl) {
    textEl.textContent = actionText;
  }
}

/**
 * 8. Dedicated Investigation Report Page (#/report)
 */
function renderReportView(data) {
  const caseIdEl = document.getElementById('reportCaseId');
  const timeEl = document.getElementById('reportTimestamp');
  const scoreEl = document.getElementById('reportScoreVal');
  const verdictEl = document.getElementById('reportVerdictVal');
  const brandEl = document.getElementById('reportBrandVal');
  const domainEl = document.getElementById('reportDomainVal');

  const tableSender = document.getElementById('reportTableSender');
  const tableSubject = document.getElementById('reportTableSubject');
  const tableUrl = document.getElementById('reportTableUrl');
  const tableBody = document.getElementById('reportTableBody');

  const findingsList = document.getElementById('reportFindingsList');
  const actionText = document.getElementById('reportActionText');

  const raw = data.rawInputs || {};
  const senderDomain = data.domain_analysis?.sender_domain || (raw.sender ? raw.sender.split('@')[1] : 'N/A');

  if (caseIdEl) caseIdEl.textContent = data.caseId || 'PG-UNKNOWN';
  if (timeEl) timeEl.textContent = data.timestamp || new Date().toLocaleString();
  if (scoreEl) scoreEl.textContent = `${data.risk_score || 0} / 100`;
  if (verdictEl) {
    verdictEl.textContent = data.verdict || 'UNKNOWN';
    verdictEl.className = data.risk_score >= 70 ? 'summary-value text-red' : (data.risk_score >= 40 ? 'summary-value text-orange' : 'summary-value text-green');
  }
  if (brandEl) brandEl.textContent = data.matched_brand || 'None (No brand targeted)';
  if (domainEl) domainEl.textContent = senderDomain;

  if (tableSender) tableSender.textContent = raw.sender || 'Not provided';
  if (tableSubject) tableSubject.textContent = raw.subject || 'Not provided';
  if (tableUrl) tableUrl.textContent = raw.url || 'Not provided';
  if (tableBody) {
    const b = raw.body || 'Not provided';
    tableBody.textContent = b.length > 300 ? b.substring(0, 300) + '... [TRUNCATED]' : b;
  }

  if (actionText) actionText.textContent = data.recommended_action || 'No action specified.';

  if (findingsList) {
    const items = [];
    if (data.domain_similarity && data.matched_brand) {
      items.push(`[CRITICAL BRAND SPOOFING] Targeted brand: ${data.matched_brand}. Similarity reason: ${data.similarity_reason}`);
    }
    (data.indicators || []).forEach(ind => {
      const name = typeof ind === 'string' ? ind : (ind.name || ind.id || '');
      const reason = typeof ind === 'string' ? '' : (ind.description || ind.reason || '');
      items.push(`[INDICATOR] ${name}${reason ? ' — ' + reason : ''}`);
    });
    (data.evidence || []).forEach(ev => {
      items.push(`[EVIDENCE] ${ev}`);
    });

    if (items.length === 0) {
      findingsList.innerHTML = '<div class="report-finding-item font-mono text-green">✔ No malicious findings or IoCs detected.</div>';
    } else {
      findingsList.innerHTML = items.map(it => `
        <div class="report-finding-item font-mono">
          <span class="finding-bullet">•</span>
          <span>${escapeHtml(it)}</span>
        </div>
      `).join('');
    }
  }
}

// ============================================================================
// DEMO / TEST PAYLOAD LOADER
// ============================================================================
function loadSamplePhishingCase() {
  const senderInput = document.getElementById('senderInput');
  const subjectInput = document.getElementById('subjectInput');
  const urlInput = document.getElementById('urlInput');
  const bodyInput = document.getElementById('emailBodyInput');

  if (senderInput) senderInput.value = 'security@paypa1-login.com';
  if (subjectInput) subjectInput.value = 'Your account will be suspended!';
  if (urlInput) urlInput.value = 'http://paypa1-login.com/verify';
  if (bodyInput) bodyInput.value = 'Verify your account immediately.';

  navigateTo('#/investigate');
  showToast('PayPal Spoof test payload loaded into investigation form.', 'info');
}

// ============================================================================
// INITIALIZATION & EVENT BINDINGS
// ============================================================================
function initApp() {
  // 1. Setup Hash Routing Listener
  window.addEventListener('hashchange', handleRouteChange);

  // 2. Initial Route Execution
  handleRouteChange();

  // 3. Form Submission
  const form = document.getElementById('investigateForm');
  if (form) {
    form.addEventListener('submit', handleInvestigationSubmit);
  }

  // 4. Sample Load Buttons
  const loadSampleBtn = document.getElementById('loadSampleBtn');
  if (loadSampleBtn) loadSampleBtn.addEventListener('click', loadSamplePhishingCase);

  const dashSampleBtn = document.getElementById('dashSampleBtn');
  if (dashSampleBtn) dashSampleBtn.addEventListener('click', loadSamplePhishingCase);

  // 5. Brand Link Navigation
  const navBrand = document.getElementById('navBrandLink');
  if (navBrand) {
    navBrand.style.cursor = 'pointer';
    navBrand.addEventListener('click', () => navigateTo('#/dashboard'));
  }

  // 6. Login Form (Demo Gate)
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', (e) => {
      e.preventDefault();
      sessionStorage.setItem(AUTH_KEY, 'analyst_active');
      showToast('Logged in as SOC Analyst (Demo Mode)', 'success');
      navigateTo('#/dashboard');
    });
  }

  // 7. Logout Button
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      sessionStorage.removeItem(AUTH_KEY);
      showToast('Analyst session ended.', 'info');
      navigateTo('#/login');
    });
  }

  // 8. Print Report Button
  const printBtn = document.getElementById('printReportBtn');
  if (printBtn) {
    printBtn.addEventListener('click', () => window.print());
  }

  // 9. Periodic Backend Health Verification
  checkBackendHealth();
  setInterval(checkBackendHealth, 15000);
}

// Boot on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
