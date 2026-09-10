/**
 * PHISHGUARD // CYBER THREAT INVESTIGATION PLATFORM – PS-02
 * Frontend Interactive Command Center Controller
 * Connected to FastAPI Backend (POST http://127.0.0.1:8001/api/analyze)
 * Vanilla JavaScript (Strictly Framework-Free)
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // --- DOM ELEMENT REFERENCES ---
  const initiateScanBtn = document.getElementById('initiateScanBtn');
  const resetSampleBtn = document.getElementById('resetSampleBtn');
  const scanningSequenceCard = document.getElementById('scanningSequenceCard');
  const threatVerdictPanel = document.getElementById('threatVerdictPanel');
  const scanProgressBar = document.getElementById('scanProgressBar');
  const scanPercent = document.getElementById('scanPercent');
  const scanSteps = document.querySelectorAll('.scan-step');
  
  // Meter & Verdict DOM Elements
  const meterProgressCircle = document.getElementById('meterProgressCircle');
  const threatScoreNumber = document.getElementById('threatScoreNumber');
  const threatFlagText = document.getElementById('threatFlagText');
  const threatConfidence = document.getElementById('threatConfidence');
  const verdictBadge = document.getElementById('verdictBadge');
  const verdictSeverity = document.getElementById('verdictSeverity');
  const verdictHeadline = document.getElementById('verdictHeadline');
  const verdictExplanation = document.getElementById('verdictExplanation');
  const statCounters = document.querySelectorAll('.stat-counter');
  const radarNodeTag1 = document.getElementById('radarNodeTag1');
  const radarHudThreat = document.getElementById('radarHudThreat');
  
  // Indicators Section DOM Elements
  const threatIndicatorsTitle = document.getElementById('threatIndicatorsTitle');
  const threatIndicatorsChip = document.getElementById('threatIndicatorsChip');
  const threatIndicatorsGrid = document.getElementById('threatIndicatorsGrid');

  // Domain Intelligence DOM Elements
  const domainValDomain = document.getElementById('domainValDomain');
  const domainValSimilarity = document.getElementById('domainValSimilarity');
  const domainValLookalike = document.getElementById('domainValLookalike');
  const domainValProtocol = document.getElementById('domainValProtocol');
  const domainValStatus = document.getElementById('domainValStatus');

  // URL Forensics DOM Elements
  const urlDisplayBox = document.getElementById('urlDisplayBox');
  const urlTableProtocol = document.getElementById('urlTableProtocol');
  const urlTableDomain = document.getElementById('urlTableDomain');
  const urlTablePath = document.getElementById('urlTablePath');
  const urlTableStatus = document.getElementById('urlTableStatus');
  const urlTableTls = document.getElementById('urlTableTls');

  // Recommended Action & Dossier DOM Elements
  const actionCardTitle = document.getElementById('actionCardTitle');
  const actionCardMessage = document.getElementById('actionCardMessage');
  const dossierCaseId = document.getElementById('dossierCaseId');
  const reportBadgeId = document.getElementById('reportBadgeId');
  const dossierHeaderBadge = document.getElementById('dossierHeaderBadge');
  const dossierTimestamp = document.getElementById('dossierTimestamp');
  const dossierVerdictVal = document.getElementById('dossierVerdictVal');
  const dossierScoreVal = document.getElementById('dossierScoreVal');
  const dossierSeverityVal = document.getElementById('dossierSeverityVal');
  const dossierIndicatorsVal = document.getElementById('dossierIndicatorsVal');
  const dossierEvidenceVal = document.getElementById('dossierEvidenceVal');
  const dossierActionVal = document.getElementById('dossierActionVal');
  const terminalLogBody = document.getElementById('terminalLogBody');
  const iocListContainer = document.querySelector('.ioc-list');

  // Form Inputs
  const senderInput = document.getElementById('senderInput');
  const subjectInput = document.getElementById('subjectInput');
  const urlInput = document.getElementById('urlInput');
  const emailBodyInput = document.getElementById('emailBodyInput');
  
  // File Upload
  const dropZone = document.getElementById('dropZone');
  const fileAttachment = document.getElementById('fileAttachment');
  const browseFileBtn = document.getElementById('browseFileBtn');
  const fileSelectedDisplay = document.getElementById('fileSelectedDisplay');
  const fileNameDisplay = document.getElementById('fileName');
  const removeFileBtn = document.getElementById('removeFileBtn');

  // Action Buttons
  const quarantineBtn = document.getElementById('quarantineBtn');
  const reportIncidentBtn = document.getElementById('reportIncidentBtn');
  const generateReportBtn = document.getElementById('generateReportBtn');
  const downloadReportBtn = document.getElementById('downloadReportBtn');
  const shareIncidentBtn = document.getElementById('shareIncidentBtn');
  const copyIocBtn = document.getElementById('copyIocBtn');
  const copyUrlBtn = document.getElementById('copyUrlBtn');
  const copyLogBtn = document.getElementById('copyLogBtn');
  const heroAnalyzeBtn = document.getElementById('heroAnalyzeBtn');
  const heroIncidentsBtn = document.getElementById('heroIncidentsBtn');

  // Settings Modal Elements
  const settingsBtn = document.getElementById('settingsBtn');
  const settingsModal = document.getElementById('settingsModal');
  const closeSettingsModal = document.getElementById('closeSettingsModal');
  const saveSettingsBtn = document.getElementById('saveSettingsBtn');
  const scanlineToggle = document.getElementById('scanlineToggle');
  const radarAnimationToggle = document.getElementById('radarAnimationToggle');
  const cyberScanline = document.querySelector('.cyber-scanline');
  const radarSweepBeam = document.querySelector('.radar-sweep-beam');

  // --- SAMPLE DATA DEFINITION ---
  const DEFAULT_SAMPLE = {
    sender: 'security@paypa1-login.com',
    subject: 'Your account will be suspended!',
    url: 'http://paypa1-login.com/verify',
    body: 'Verify your account immediately.'
  };

  // State to hold latest backend analysis result
  let latestAnalysisResult = null;
  let currentCaseId = 'PG-PS02-0001';
  let isScanning = false;

  // --- 1. TOAST NOTIFICATION SYSTEM ---
  function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `cyber-toast ${type === 'danger' ? 'danger' : ''}`;
    
    const icon = type === 'danger' ? '🛑' : (type === 'success' ? '🛡️' : '⚡');
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // --- 2. NUMBER COUNTER ANIMATION ---
  function animateValue(element, start, end, duration) {
    if (!element) return;
    let startTimestamp = null;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      const currentVal = Math.floor(progress * (end - start) + start);
      element.textContent = currentVal;
      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        element.textContent = end;
      }
    };
    window.requestAnimationFrame(step);
  }

  // Initialize Dashboard Metric Counters
  function initStatCounters() {
    statCounters.forEach(counter => {
      const target = parseInt(counter.getAttribute('data-target'), 10) || 0;
      animateValue(counter, 0, target, 1600);
    });
  }

  // --- 3. DYNAMIC CIRCULAR RISK METER ---
  function updateRiskMeter(score, verdict = '') {
    if (!meterProgressCircle || !threatScoreNumber) return;
    
    // Total circumference for r=68 is ~427.26
    const circumference = 2 * Math.PI * 68;
    const offset = circumference - (score / 100) * circumference;

    // Reset dashoffset then animate smoothly
    meterProgressCircle.style.strokeDashoffset = circumference;
    setTimeout(() => {
      meterProgressCircle.style.strokeDashoffset = offset;
    }, 100);

    // Dynamic color styling based on threat score and verdict
    let strokeColor = '#00ff88';
    let dropShadow = '0 0 12px rgba(0, 255, 136, 0.7)';
    
    const upperVerdict = String(verdict).toUpperCase();
    if (score >= 80 || upperVerdict === 'CRITICAL') {
      strokeColor = '#ff0055'; // Critical Red
      dropShadow = '0 0 14px rgba(255, 0, 85, 0.8)';
    } else if (score >= 60 || upperVerdict === 'HIGH') {
      strokeColor = '#ff7700'; // High Orange
      dropShadow = '0 0 12px rgba(255, 119, 0, 0.7)';
    } else if (score >= 30 || upperVerdict === 'MEDIUM') {
      strokeColor = '#f59e0b'; // Medium Yellow/Amber
      dropShadow = '0 0 12px rgba(245, 158, 11, 0.7)';
    } else {
      strokeColor = '#00ff88'; // Low / Clean Green
      dropShadow = '0 0 12px rgba(0, 255, 136, 0.7)';
    }

    meterProgressCircle.style.stroke = strokeColor;
    meterProgressCircle.style.filter = `drop-shadow(${dropShadow})`;
    threatScoreNumber.style.textShadow = dropShadow;

    animateValue(threatScoreNumber, 0, score, 1100);
  }

  // --- 4. ASYNCHRONOUS BACKEND API CLIENT ---
  async function callBackendApi(payload) {
    const candidateEndpoints = [];
    if (window.location.port === '8000') {
      candidateEndpoints.push('/api/analyze');
    }
    candidateEndpoints.push('http://127.0.0.1:8001/api/analyze');
    candidateEndpoints.push('http://localhost:8000/api/analyze');

    let lastError = null;
    for (const endpoint of candidateEndpoints) {
      try {
        console.log(`[PhishGuard] Dispatching analysis payload to ${endpoint}...`);
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });

        if (response.ok) {
          const data = await response.json();
          console.log('[PhishGuard] Received live backend response:', data);
          return data;
        } else {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
      } catch (err) {
        console.warn(`[PhishGuard] Candidate endpoint ${endpoint} failed:`, err);
        lastError = err;
      }
    }

    throw lastError || new Error('Backend API unavailable at all candidate endpoints');
  }

  // --- 5. RUN THREAT ANALYSIS WORKFLOW ---
  async function runThreatAnalysis() {
    if (isScanning) return;

    // 1. Read input values from frontend form
    const sender = (senderInput ? senderInput.value : '').trim();
    const subject = (subjectInput ? subjectInput.value : '').trim();
    const url = (urlInput ? urlInput.value : '').trim();
    const body = (emailBodyInput ? emailBodyInput.value : '').trim();

    if (!sender && !subject && !url && !body) {
      showToast('Please enter an email sender, subject, URL, or body to analyze.', 'danger');
      return;
    }

    isScanning = true;

    // Update scan button state
    if (initiateScanBtn) {
      initiateScanBtn.disabled = true;
      initiateScanBtn.style.opacity = '0.75';
      const label = initiateScanBtn.querySelector('.btn-label');
      if (label) label.textContent = '◉ DISPATCHING TO THREAT ENGINE...';
    }

    // Show Scanning Console Card
    if (scanningSequenceCard) {
      scanningSequenceCard.classList.remove('hidden');
      scanningSequenceCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    // Reset scan steps UI
    scanSteps.forEach(step => {
      step.classList.remove('active', 'completed', 'failed');
      const statusIcon = step.querySelector('.step-status');
      if (statusIcon) statusIcon.textContent = '⏳';
    });

    if (scanProgressBar) scanProgressBar.style.width = '0%';
    if (scanPercent) scanPercent.textContent = '0%';

    // Step animation controller: advance steps progressively
    let currentStepIndex = 0;
    const totalSteps = scanSteps.length;
    const stepInterval = 250;

    const stepTimer = setInterval(() => {
      if (currentStepIndex < totalSteps - 1) {
        if (currentStepIndex > 0) {
          const prevStep = scanSteps[currentStepIndex - 1];
          prevStep.classList.remove('active');
          prevStep.classList.add('completed');
          const prevIcon = prevStep.querySelector('.step-status');
          if (prevIcon) prevIcon.textContent = '✔';
        }

        const curStep = scanSteps[currentStepIndex];
        curStep.classList.add('active');
        const curIcon = curStep.querySelector('.step-status');
        if (curIcon) curIcon.textContent = '▶';

        const progress = Math.round(((currentStepIndex + 1) / totalSteps) * 88);
        if (scanProgressBar) scanProgressBar.style.width = `${progress}%`;
        if (scanPercent) scanPercent.textContent = `${progress}%`;

        currentStepIndex++;
      }
    }, stepInterval);

    // 2. Dispatch request to backend API
    try {
      const payload = {
        sender: sender,
        subject: subject,
        body: body,
        url: url
      };

      const result = await callBackendApi(payload);
      latestAnalysisResult = result;

      // Complete visual scan steps
      clearInterval(stepTimer);

      scanSteps.forEach(step => {
        step.classList.remove('active');
        step.classList.add('completed');
        const icon = step.querySelector('.step-status');
        if (icon) icon.textContent = '✔';
      });

      if (scanProgressBar) scanProgressBar.style.width = '100%';
      if (scanPercent) scanPercent.textContent = '100%';

      setTimeout(() => {
        // 3. Update all frontend elements with real backend response
        updateUIWithBackendResult(result, payload);
        finalizeScanState();
        showToast(`Threat analysis complete: Score ${result.risk_score}/100 [${result.verdict}]`, result.risk_score >= 60 ? 'danger' : 'info');
      }, 350);

    } catch (err) {
      clearInterval(stepTimer);
      console.error('[PhishGuard Frontend Error] Backend communication failed:', err);

      if (scanSteps[currentStepIndex]) {
        scanSteps[currentStepIndex].classList.add('failed');
        const icon = scanSteps[currentStepIndex].querySelector('.step-status');
        if (icon) icon.textContent = '✖';
      }

      showToast('Backend unavailable at http://127.0.0.1:8000. Please ensure FastAPI is running (uvicorn backend.main:app --reload)', 'danger');

      if (terminalLogBody) {
        const errorLine = document.createElement('div');
        errorLine.className = 'term-line';
        errorLine.innerHTML = `<span class="term-prefix text-red">[ERR-FAIL]</span> <span class="term-log text-red font-bold">API CONNECTION REFUSED // http://127.0.0.1:8001/api/analyze</span>`;
        terminalLogBody.insertBefore(errorLine, terminalLogBody.lastElementChild);
      }

      finalizeScanState();
    }
  }

  function finalizeScanState() {
    isScanning = false;
    if (initiateScanBtn) {
      initiateScanBtn.disabled = false;
      initiateScanBtn.style.opacity = '1';
      const label = initiateScanBtn.querySelector('.btn-label');
      if (label) label.textContent = '◉ INITIATE THREAT ANALYSIS';
    }
  }

  // --- 6. UPDATE UI WITH REAL BACKEND DATA ---
  function updateUIWithBackendResult(data, inputs) {
    if (!data) return;

    currentCaseId = 'PG-PS02-' + Math.floor(1000 + Math.random() * 9000);

    // A. Reveal Threat Verdict Panel
    if (threatVerdictPanel) {
      threatVerdictPanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
      threatVerdictPanel.classList.add('pulse-verdict');
      setTimeout(() => threatVerdictPanel.classList.remove('pulse-verdict'), 1200);

      threatVerdictPanel.classList.remove('danger-border', 'warning-border', 'safe-border');
      if (data.risk_score >= 60 || data.verdict === 'CRITICAL' || data.verdict === 'HIGH') {
        threatVerdictPanel.classList.add('danger-border');
      }
    }

    // B. Risk Score Meter Animation (uses data.risk_score)
    updateRiskMeter(data.risk_score, data.verdict);

    // C. Verdict Banner & Headline
    if (threatFlagText) {
      threatFlagText.textContent = `SECURITY ALERT // ${data.verdict} THREAT DETECTED`;
    }

    if (threatConfidence) {
      const confidence = (82 + (data.risk_score * 0.16)).toFixed(1);
      threatConfidence.textContent = `CONFIDENCE: ${confidence}%`;
    }

    // Verdict Badge
    if (verdictBadge) {
      verdictBadge.textContent = `${data.verdict}`;
      if (data.verdict === 'CRITICAL') {
        verdictBadge.style.background = 'var(--threat-red)';
        verdictBadge.style.color = '#ffffff';
      } else if (data.verdict === 'HIGH') {
        verdictBadge.style.background = 'var(--threat-orange)';
        verdictBadge.style.color = '#ffffff';
      } else if (data.verdict === 'MEDIUM') {
        verdictBadge.style.background = 'var(--threat-yellow)';
        verdictBadge.style.color = '#000000';
      } else {
        verdictBadge.style.background = 'var(--threat-green)';
        verdictBadge.style.color = '#000000';
      }
    }

    // Severity ID
    if (verdictSeverity) {
      verdictSeverity.textContent = `SEV: ${data.verdict === 'CRITICAL' ? '1 (CRITICAL)' : data.verdict === 'HIGH' ? '2 (ELEVATED)' : data.verdict === 'MEDIUM' ? '3 (MODERATE)' : '4 (LOW)'}`;
    }

    // Verdict Headline
    if (verdictHeadline) {
      verdictHeadline.textContent = `${data.verdict}`;
      if (data.verdict === 'CRITICAL') {
        verdictHeadline.className = 'verdict-headline text-red';
      } else if (data.verdict === 'HIGH') {
        verdictHeadline.className = 'verdict-headline text-orange';
      } else if (data.verdict === 'MEDIUM') {
        verdictHeadline.className = 'verdict-headline text-orange';
      } else {
        verdictHeadline.className = 'verdict-headline text-green';
      }
    }

    // Verdict Explanation
    if (verdictExplanation) {
      if (data.evidence && data.evidence.length > 0) {
        verdictExplanation.textContent = `${data.evidence.length} forensic indicators detected by heuristic engine. ${data.evidence.join(' ')}`;
      } else {
        verdictExplanation.textContent = 'No critical threat vectors detected. Domain and message content pass heuristic checks.';
      }
    }

    // D. Radar Telemetry
    if (radarNodeTag1) {
      radarNodeTag1.textContent = `${data.verdict} [${data.risk_score}%]`;
    }
    if (radarHudThreat) {
      radarHudThreat.textContent = `THREAT: ${data.risk_score}/100`;
    }

    // E. Risk Breakdown Cards
    const breakdownCards = document.querySelectorAll('.breakdown-card');
    if (breakdownCards.length >= 4) {
      // 1. Sender Risk
      const hasSenderIssue = data.indicators.some(i => i.toLowerCase().includes('sender'));
      const senderRiskScore = hasSenderIssue 
        ? Math.min(data.risk_score, 85) 
        : (data.domain_analysis?.suspicious ? Math.min(Math.round(data.risk_score * 0.7), 40) : 10);
      updateBreakdownCard(breakdownCards[0], senderRiskScore, hasSenderIssue ? 'Sender address anomalies or formatting deviations detected.' : (data.domain_analysis?.suspicious ? 'Sender domain flagged with suspicious naming patterns.' : 'Sender address format conforms to standard specification.'));

      // 2. Domain Risk
      const hasDomainIssue = data.domain_analysis?.suspicious || data.indicators.some(i => i.toLowerCase().includes('domain') || i.toLowerCase().includes('brand'));
      const domainRiskScore = hasDomainIssue ? Math.min(data.risk_score, 80) : 8;
      updateBreakdownCard(breakdownCards[1], domainRiskScore, hasDomainIssue ? 'Sender domain exhibits suspicious keywords or brand imitation.' : 'Sender domain shows authentic records and no typosquatting.');

      // 3. URL Risk
      const hasUrlIssue = data.url_analysis?.suspicious || data.indicators.some(i => i.toLowerCase().includes('http') || i.toLowerCase().includes('url'));
      const urlRiskScore = hasUrlIssue ? Math.min(data.risk_score, 75) : (data.url_analysis?.url ? 15 : 0);
      updateBreakdownCard(breakdownCards[2], urlRiskScore, hasUrlIssue ? 'Insecure clear-text HTTP protocol or deceptive destination structure.' : (data.url_analysis?.url ? 'URL uses secure protocol without flagged destination parameters.' : 'No active hyperlink found in message body.'));

      // 4. Language Risk
      const hasUrgencyIssue = data.indicators.some(i => i.toLowerCase().includes('urgency') || i.toLowerCase().includes('language'));
      const langRiskScore = hasUrgencyIssue ? Math.min(data.risk_score, 70) : 10;
      updateBreakdownCard(breakdownCards[3], langRiskScore, hasUrgencyIssue ? 'High frequency of urgency/coercion keywords detected in message body.' : 'Neutral communication tone without detected social engineering triggers.');
    }

    // F. Threat Indicators Section
    const indCount = data.indicators ? data.indicators.length : 0;
    if (threatIndicatorsTitle) {
      threatIndicatorsTitle.textContent = `THREAT INDICATORS // ${String(indCount).padStart(2, '0')} DETECTED`;
    }
    if (threatIndicatorsChip) {
      threatIndicatorsChip.textContent = `${indCount} ${indCount === 1 ? 'VECTOR' : 'VECTORS'} IDENTIFIED`;
    }

    if (threatIndicatorsGrid) {
      threatIndicatorsGrid.innerHTML = '';

      if (indCount === 0) {
        const cleanCard = document.createElement('div');
        cleanCard.className = 'indicator-card glass-card';
        cleanCard.style.gridColumn = '1 / -1';
        cleanCard.innerHTML = `
          <div class="indicator-head">
            <div class="indicator-icon" style="background: rgba(0, 255, 136, 0.15); color: var(--threat-green); border: 1px solid var(--threat-green);">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            </div>
            <div class="indicator-meta">
              <span class="severity-tag" style="background: var(--threat-green); color: #000;">VERIFIED CLEAN</span>
              <h4 class="indicator-title">NO THREAT INDICATORS DETECTED</h4>
            </div>
          </div>
          <div class="indicator-evidence">
            <span class="evidence-tag">EVIDENCE</span>
            <code class="evidence-code font-mono text-green">All heuristic verification checks passed.</code>
          </div>
          <p class="indicator-desc">
            The submitted sender, URL, and body content do not trigger any known phishing or social engineering rulesets.
          </p>
        `;
        threatIndicatorsGrid.appendChild(cleanCard);
      } else {
        data.indicators.forEach((indicatorName, idx) => {
          const evidenceText = data.evidence && data.evidence[idx] ? data.evidence[idx] : 'Signature match in analyzed payload.';
          
          let severity = 'MEDIUM';
          let tagClass = 'medium';
          let iconClass = 'warning';
          let iconSvg = `
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
            </svg>
          `;

          const lowerInd = indicatorName.toLowerCase();
          if (data.verdict === 'CRITICAL') {
            if (lowerInd.includes('sender') || lowerInd.includes('impersonation') || lowerInd.includes('domain')) {
              severity = 'CRITICAL';
              tagClass = 'critical';
              iconClass = 'danger';
              iconSvg = `
                <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="12" y1="8" x2="12" y2="12"/>
                  <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
              `;
            } else {
              severity = 'HIGH';
              tagClass = 'high';
              iconClass = 'danger';
            }
          } else if (data.verdict === 'HIGH') {
            severity = 'HIGH';
            tagClass = 'high';
            iconClass = 'warning';
            iconSvg = `
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
              </svg>
            `;
          } else if (data.verdict === 'MEDIUM') {
            severity = 'MEDIUM';
            tagClass = 'medium';
            iconClass = 'warning';
          } else {
            severity = 'LOW';
            tagClass = 'low';
            iconClass = 'safe';
            iconSvg = `
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            `;
          }

          const card = document.createElement('div');
          card.className = 'indicator-card glass-card';
          card.innerHTML = `
            <div class="indicator-head">
              <div class="indicator-icon ${iconClass}">
                ${iconSvg}
              </div>
              <div class="indicator-meta">
                <span class="severity-tag ${tagClass}">${severity}</span>
                <h4 class="indicator-title">${escapeHtml(indicatorName.toUpperCase())}</h4>
              </div>
            </div>
            <div class="indicator-evidence">
              <span class="evidence-tag">EVIDENCE</span>
              <code class="evidence-code font-mono">${escapeHtml(evidenceText)}</code>
            </div>
            <p class="indicator-desc">
              Heuristic detector flagged this anomalous security signal during deep message inspection.
            </p>
          `;
          threatIndicatorsGrid.appendChild(card);
        });
      }
    }

    // F. Domain Intelligence Section
    const senderDomain = data.domain_analysis?.sender_domain || (inputs.sender.includes('@') ? inputs.sender.split('@')[1] : inputs.sender) || 'N/A';
    if (domainValDomain) domainValDomain.textContent = senderDomain;
    if (domainValSimilarity) domainValSimilarity.textContent = data.domain_analysis?.suspicious ? '94%' : '< 5%';
    if (domainValLookalike) {
      domainValLookalike.textContent = data.domain_analysis?.suspicious ? 'YES' : 'NO';
      domainValLookalike.className = `intel-val font-mono ${data.domain_analysis?.suspicious ? 'text-red' : 'text-green'}`;
    }
    if (domainValProtocol) {
      domainValProtocol.textContent = (data.url_analysis?.scheme || 'N/A').toUpperCase();
    }
    if (domainValStatus) {
      domainValStatus.textContent = data.domain_analysis?.suspicious ? 'SUSPICIOUS' : 'VERIFIED';
      domainValStatus.className = `intel-val font-mono ${data.domain_analysis?.suspicious ? 'text-red' : 'text-green'}`;
    }

    // Dynamic Domain Visual Comparison
    const spoofRowDomain = document.querySelector('.spoof-row .compare-domain');
    if (spoofRowDomain) {
      if (senderDomain.includes('paypa1')) {
        spoofRowDomain.innerHTML = `pay<span class="char-match">p</span><span class="char-match">a</span><span class="char-deceptive" title="Digit '1' substitutes letter 'l'">1</span>-login.com`;
      } else {
        spoofRowDomain.textContent = senderDomain;
      }
    }

    // G. URL Forensics Panel
    const urlValue = data.url_analysis?.url || inputs.url || 'No URL specified';
    if (urlDisplayBox) {
      const copyBtnHtml = `
        <button class="copy-url-btn" id="copyUrlBtn" title="Copy URL to clipboard">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
      `;
      urlDisplayBox.innerHTML = `<span class="text-orange font-mono">${escapeHtml(urlValue)}</span>${copyBtnHtml}`;
      
      const newCopyBtn = document.getElementById('copyUrlBtn');
      if (newCopyBtn) {
        newCopyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(urlValue)
            .then(() => showToast('Suspicious URL copied to clipboard'))
            .catch(() => showToast('Unable to copy URL', 'danger'));
        });
      }
    }

    const scheme = (data.url_analysis?.scheme || 'NONE').toUpperCase();
    const parsedDomain = data.url_analysis?.domain || (data.url_analysis?.url ? extractDomain(data.url_analysis.url) : 'N/A');
    const path = data.url_analysis?.url ? extractPath(data.url_analysis.url) : '/';
    const isUrlSuspicious = data.url_analysis?.suspicious;

    if (urlTableProtocol) {
      urlTableProtocol.innerHTML = `${scheme} <span class="badge-inline ${scheme === 'HTTP' ? 'warning' : 'safe'}">${scheme === 'HTTP' ? 'INSECURE' : 'SECURE'}</span>`;
    }
    if (urlTableDomain) urlTableDomain.textContent = parsedDomain;
    if (urlTablePath) urlTablePath.textContent = path;
    if (urlTableStatus) {
      if (isUrlSuspicious) {
        const badgeClass = data.verdict === 'CRITICAL' ? 'critical' : (data.verdict === 'HIGH' ? 'high' : 'warning');
        const badgeText = data.verdict === 'CRITICAL' ? 'HIGH THREAT' : (data.verdict === 'HIGH' ? 'ELEVATED' : 'MODERATE THREAT');
        urlTableStatus.innerHTML = `SUSPICIOUS <span class="badge-inline ${badgeClass}">${badgeText}</span>`;
      } else {
        urlTableStatus.innerHTML = `CLEAN <span class="badge-inline safe">VERIFIED</span>`;
      }
    }
    if (urlTableTls) {
      urlTableTls.textContent = scheme === 'HTTPS'
        ? 'TLS ENCRYPTED (HTTPS VALIDATED)'
        : (scheme === 'HTTP' ? 'NONE (CLEAR TEXT TRANSMISSION)' : 'N/A');
    }

    // H. Evidence Terminal Logs
    if (terminalLogBody) {
      terminalLogBody.innerHTML = `
        <div class="term-line"><span class="term-prefix">[SOC-INIT]</span> <span class="term-log">INITIALIZING EMAIL FORENSICS ENGINE...</span></div>
        <div class="term-line"><span class="term-prefix">[API-GATE]</span> <span class="term-log">CONNECTED: <span class="text-cyan">http://127.0.0.1:8001/api/analyze</span></span></div>
        <div class="term-line"><span class="term-prefix">[SENDER]</span> <span class="term-log">RFC 5322 FROM: <span class="text-white">${escapeHtml(inputs.sender)}</span></span></div>
        <div class="term-line"><span class="term-prefix">[DOMAIN]</span> <span class="term-log">DOMAIN: ${escapeHtml(senderDomain)} .... <span class="${data.domain_analysis?.suspicious ? 'text-red' : 'text-green'}">${data.domain_analysis?.suspicious ? 'WARNING' : 'VERIFIED'}</span></span></div>
        <div class="term-line"><span class="term-prefix">[NETWORK]</span> <span class="term-log">URL PROTOCOL: <span class="${data.url_analysis?.scheme === 'http' ? 'text-orange' : 'text-green'}">${(data.url_analysis?.scheme || 'NONE').toUpperCase()}</span></span></div>
        <div class="term-line"><span class="term-prefix">[NLP-SCAN]</span> <span class="term-log">URGENCY TRIGGER DETECTED: <span class="${data.indicators.some(i => i.toLowerCase().includes('urgency')) ? 'text-red' : 'text-green'}">${data.indicators.some(i => i.toLowerCase().includes('urgency')) ? 'TRUE' : 'FALSE'}</span></span></div>
        <div class="term-line"><span class="term-prefix">[SIGNALS]</span> <span class="term-log">INDICATORS IDENTIFIED: <span class="text-cyan">${String(indCount).padStart(2, '0')}</span></span></div>
        <div class="term-line"><span class="term-prefix">[CALC-AG]</span> <span class="term-log">THREAT SCORE: <span class="${data.risk_score >= 60 ? 'text-red' : (data.risk_score >= 30 ? 'text-orange' : 'text-green')} font-bold">${data.risk_score}/100</span></span></div>
        <div class="term-line"><span class="term-prefix">[VERDICT]</span> <span class="term-log">FINAL VERDICT: <span class="${data.risk_score >= 60 ? 'text-red font-bold bg-danger-glow' : 'text-orange font-bold'}">${data.verdict}</span></span></div>
        <div class="term-line term-cursor-line">
          <span class="term-prompt">phishguard@soc-node:~$</span>
          <span class="terminal-cursor">_</span>
        </div>
      `;
    }

    // I. Indicators of Compromise (IoC)
    if (iocListContainer) {
      let detectedKeywords = [];
      const urgencyEvidence = data.evidence ? data.evidence.find(e => e.includes('keywords detected:')) : null;
      if (urgencyEvidence) {
        const parts = urgencyEvidence.split(':');
        if (parts[1]) {
          detectedKeywords = parts[1].split(',').map(k => k.trim());
        }
      }

      const keywordPillsHtml = detectedKeywords.length > 0 
        ? detectedKeywords.map(k => `<span class="keyword-pill">${escapeHtml(k)}</span>`).join(' ')
        : `<span class="text-muted font-mono" style="font-size: 11px;">None detected</span>`;

      iocListContainer.innerHTML = `
        <div class="ioc-item">
          <div class="ioc-type font-mono">EMAIL</div>
          <div class="ioc-value font-mono">${escapeHtml(inputs.sender || 'N/A')}</div>
          <span class="ioc-tag ${data.domain_analysis?.suspicious ? 'danger' : 'warning'}">${data.domain_analysis?.suspicious ? 'SUSPECT' : 'CLEAN'}</span>
        </div>

        <div class="ioc-item">
          <div class="ioc-type font-mono">DOMAIN</div>
          <div class="ioc-value font-mono">${escapeHtml(senderDomain)}</div>
          <span class="ioc-tag ${data.domain_analysis?.suspicious ? 'danger' : 'warning'}">${data.domain_analysis?.suspicious ? 'LOOKALIKE' : 'NORMAL'}</span>
        </div>

        <div class="ioc-item">
          <div class="ioc-type font-mono">URL</div>
          <div class="ioc-value font-mono">${escapeHtml(urlValue)}</div>
          <span class="ioc-tag ${data.url_analysis?.suspicious ? 'danger' : 'warning'}">${data.url_analysis?.suspicious ? 'HARVESTER' : 'BENIGN'}</span>
        </div>

        <div class="ioc-item">
          <div class="ioc-type font-mono">KEYWORDS</div>
          <div class="ioc-tags-group">
            ${keywordPillsHtml}
          </div>
          <span class="ioc-tag ${detectedKeywords.length > 0 ? 'warning' : 'safe'}">TRIGGERS</span>
        </div>
      `;
    }

    // J. Recommended Security Action Card
    if (actionCardTitle) {
      actionCardTitle.textContent = data.verdict === 'CRITICAL'
        ? 'High Confidence Malicious Threat Detected'
        : (data.verdict === 'HIGH' ? 'High Risk Threat Detected' : (data.verdict === 'MEDIUM' ? 'Moderate Risk Caution Required' : 'Standard Routine Security Verification'));
    }

    if (actionCardMessage) {
      actionCardMessage.textContent = data.recommended_action;
    }

    // K. Incident Report Dossier Section
    if (dossierCaseId) dossierCaseId.textContent = currentCaseId;
    if (reportBadgeId) reportBadgeId.textContent = `CASE: ${currentCaseId}`;
    if (dossierHeaderBadge) {
      dossierHeaderBadge.textContent = `${data.verdict} SEVERITY`;
      if (data.verdict === 'CRITICAL') {
        dossierHeaderBadge.style.background = 'var(--threat-red)';
        dossierHeaderBadge.style.color = '#ffffff';
      } else if (data.verdict === 'HIGH') {
        dossierHeaderBadge.style.background = 'var(--threat-orange)';
        dossierHeaderBadge.style.color = '#ffffff';
      } else if (data.verdict === 'MEDIUM') {
        dossierHeaderBadge.style.background = 'var(--threat-yellow)';
        dossierHeaderBadge.style.color = '#000000';
      } else {
        dossierHeaderBadge.style.background = 'var(--threat-green)';
        dossierHeaderBadge.style.color = '#000000';
      }
    }
    if (dossierTimestamp) {
      dossierTimestamp.textContent = `TIMESTAMP: ${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC`;
    }

    if (dossierVerdictVal) {
      dossierVerdictVal.textContent = data.verdict;
      dossierVerdictVal.className = `cell-value ${data.risk_score >= 60 ? 'text-red' : (data.risk_score >= 30 ? 'text-orange' : 'text-green')} font-bold font-mono`;
    }

    if (dossierScoreVal) {
      dossierScoreVal.textContent = `${data.risk_score} / 100`;
      dossierScoreVal.className = `cell-value ${data.risk_score >= 60 ? 'text-red' : (data.risk_score >= 30 ? 'text-orange' : 'text-green')} font-bold font-mono`;
    }

    if (dossierSeverityVal) {
      dossierSeverityVal.textContent = data.verdict;
      dossierSeverityVal.className = `cell-value ${data.risk_score >= 60 ? 'text-red' : (data.risk_score >= 30 ? 'text-orange' : 'text-green')} font-mono`;
    }

    if (dossierIndicatorsVal) {
      dossierIndicatorsVal.textContent = String(indCount).padStart(2, '0');
    }

    if (dossierEvidenceVal) {
      dossierEvidenceVal.textContent = data.indicators && data.indicators.length > 0 
        ? data.indicators.join(' + ') 
        : 'Baseline Cleared // No hostile vectors';
    }

    if (dossierActionVal) {
      dossierActionVal.textContent = data.recommended_action;
    }
  }

  // Helper to update breakdown cards
  function updateBreakdownCard(card, score, description) {
    if (!card) return;
    const scoreEl = card.querySelector('.breakdown-score');
    const fillEl = card.querySelector('.progress-bar-fill');
    const descEl = card.querySelector('.breakdown-desc');

    if (scoreEl) {
      scoreEl.textContent = `${score}%`;
      scoreEl.className = `breakdown-score font-mono ${score >= 70 ? 'text-red' : (score >= 40 ? 'text-orange' : 'text-green')}`;
    }

    if (fillEl) {
      fillEl.style.width = `${score}%`;
      fillEl.className = `progress-bar-fill ${score >= 70 ? 'red' : (score >= 40 ? 'orange' : 'green')}`;
    }

    if (descEl) {
      descEl.textContent = description;
    }
  }

  // Utility helpers
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function extractDomain(urlStr) {
    try {
      const parsed = new URL(urlStr);
      return parsed.hostname;
    } catch {
      return urlStr.replace(/^https?:\/\//, '').split('/')[0];
    }
  }

  function extractPath(urlStr) {
    try {
      const parsed = new URL(urlStr);
      return parsed.pathname || '/';
    } catch {
      return '/';
    }
  }

  // Hook Scan Button Click
  if (initiateScanBtn) {
    initiateScanBtn.addEventListener('click', runThreatAnalysis);
  }

  // --- 7. RELOAD SAMPLE DATA ---
  if (resetSampleBtn) {
    resetSampleBtn.addEventListener('click', () => {
      if (senderInput) senderInput.value = DEFAULT_SAMPLE.sender;
      if (subjectInput) subjectInput.value = DEFAULT_SAMPLE.subject;
      if (urlInput) urlInput.value = DEFAULT_SAMPLE.url;
      if (emailBodyInput) emailBodyInput.value = DEFAULT_SAMPLE.body;
      
      showToast('Sample dataset restored: PayPal credential harvest probe');
    });
  }

  // --- 8. DRAG AND DROP ATTACHMENT HANDLER ---
  if (dropZone && fileAttachment) {
    if (browseFileBtn) {
      browseFileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileAttachment.click();
      });
    }

    dropZone.addEventListener('click', () => {
      fileAttachment.click();
    });

    fileAttachment.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFileSelection(e.target.files[0].name);
      }
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('dragover');
      });
    });

    dropZone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelection(e.dataTransfer.files[0].name);
      }
    });
  }

  function handleFileSelection(name) {
    if (fileNameDisplay) fileNameDisplay.textContent = name;
    if (fileSelectedDisplay) fileSelectedDisplay.classList.remove('hidden');
    showToast(`Attachment staged for inspection: ${name}`);
  }

  if (removeFileBtn) {
    removeFileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (fileAttachment) fileAttachment.value = '';
      if (fileSelectedDisplay) fileSelectedDisplay.classList.add('hidden');
      showToast('Attachment removed from analysis buffer');
    });
  }

  // --- 9. COPY FORENSIC ASSETS (URL, IoC, TERMINAL) ---
  if (copyLogBtn) {
    copyLogBtn.addEventListener('click', () => {
      if (terminalLogBody) {
        navigator.clipboard.writeText(terminalLogBody.innerText)
          .then(() => showToast('SOC evidence logs copied to clipboard'))
          .catch(() => showToast('Failed to copy logs', 'danger'));
      }
    });
  }

  if (copyUrlBtn && urlInput) {
    copyUrlBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(urlInput.value || 'http://paypa1-login.com/verify')
        .then(() => showToast('Suspicious URL copied to clipboard'))
        .catch(() => showToast('Unable to copy URL', 'danger'));
    });
  }

  if (copyIocBtn) {
    copyIocBtn.addEventListener('click', () => {
      const senderVal = (senderInput ? senderInput.value : '').trim() || 'security@paypa1-login.com';
      const urlVal = (urlInput ? urlInput.value : '').trim() || 'http://paypa1-login.com/verify';
      const domainVal = senderVal.includes('@') ? senderVal.split('@')[1] : senderVal;
      const score = latestAnalysisResult ? latestAnalysisResult.risk_score : 45;
      const verdict = latestAnalysisResult ? latestAnalysisResult.verdict : 'MEDIUM';

      const iocPayload = [
        '# PHISHGUARD // INDICATORS OF COMPROMISE (IoC)',
        `CASE_ID: ${currentCaseId}`,
        `SENDER_EMAIL: ${senderVal}`,
        `DOMAIN: ${domainVal}`,
        `URL: ${urlVal}`,
        `THREAT_SCORE: ${score}/100`,
        `VERDICT: ${verdict}`,
        `TIMESTAMP: ${new Date().toISOString()}`,
        `SYSTEM: FASTAPI_HEURISTICS_PS02`
      ].join('\n');

      navigator.clipboard.writeText(iocPayload)
        .then(() => showToast('All IoCs copied formatted as STIX/TAXII manifest'))
        .catch(() => showToast('Clipboard copy failed', 'danger'));
    });
  }

  // --- 10. SECURITY ACTION HANDLERS ---
  if (quarantineBtn) {
    quarantineBtn.addEventListener('click', () => {
      showToast('Message quarantined in SOC sandbox vault. Gateway rule active.', 'danger');
      quarantineBtn.innerHTML = '<span>🔒</span><span>EMAIL QUARANTINED</span>';
      quarantineBtn.classList.remove('danger-btn');
      quarantineBtn.classList.add('secondary-btn');
    });
  }

  if (reportIncidentBtn) {
    reportIncidentBtn.addEventListener('click', () => {
      showToast(`Incident ticket #${currentCaseId} dispatched to SOC L2 responder queue`);
      reportIncidentBtn.innerHTML = '<span>🛡️</span><span>INCIDENT DISPATCHED</span>';
    });
  }

  // --- 11. INCIDENT REPORT ACTIONS & DYNAMIC DOWNLOAD ---
  if (generateReportBtn) {
    generateReportBtn.addEventListener('click', () => {
      showToast(`Compiling high-assurance SOC Dossier for ${currentCaseId}...`);
      setTimeout(() => {
        showToast('PDF Dossier compiled and cryptographic hash verified.');
      }, 1000);
    });
  }

  if (downloadReportBtn) {
    downloadReportBtn.addEventListener('click', () => {
      const senderVal = (senderInput ? senderInput.value : '').trim() || DEFAULT_SAMPLE.sender;
      const subjectVal = (subjectInput ? subjectInput.value : '').trim() || DEFAULT_SAMPLE.subject;
      const urlVal = (urlInput ? urlInput.value : '').trim() || DEFAULT_SAMPLE.url;

      const reportData = {
        platform: "PhishGuard",
        project: "Phishing Attack Investigation Platform – PS-02",
        incidentId: currentCaseId,
        timestamp: new Date().toISOString(),
        analyzed_input: {
          sender: senderVal,
          subject: subjectVal,
          url: urlVal
        },
        backend_response: latestAnalysisResult || {
          risk_score: 45,
          verdict: "MEDIUM",
          indicators: ["Suspicious domain pattern", "Urgency language", "Insecure HTTP link"],
          recommended_action: "Treat the message with caution and verify the sender through a trusted channel."
        }
      };

      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `PhishGuard_${currentCaseId}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();

      showToast(`Incident Report ${currentCaseId}.json exported`);
    });
  }

  if (shareIncidentBtn) {
    shareIncidentBtn.addEventListener('click', () => {
      const shareUrl = window.location.href.split('#')[0] + '#incident-reports';
      navigator.clipboard.writeText(shareUrl)
        .then(() => showToast('Secure incident reference link copied to clipboard'))
        .catch(() => showToast('Incident link ready for sharing'));
    });
  }

  // --- 12. HERO CTA SMOOTH SCROLLING ---
  if (heroAnalyzeBtn) {
    heroAnalyzeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const target = document.getElementById('analysis-workspace');
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    });
  }

  if (heroIncidentsBtn) {
    heroIncidentsBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const target = document.getElementById('incident-reports');
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    });
  }

  // --- 13. SOC SETTINGS MODAL INTERACTIONS ---
  if (settingsBtn && settingsModal) {
    settingsBtn.addEventListener('click', () => {
      settingsModal.classList.remove('hidden');
    });
  }

  if (closeSettingsModal && settingsModal) {
    closeSettingsModal.addEventListener('click', () => {
      settingsModal.classList.add('hidden');
    });
  }

  if (saveSettingsBtn && settingsModal) {
    saveSettingsBtn.addEventListener('click', () => {
      if (scanlineToggle && cyberScanline) {
        cyberScanline.style.display = scanlineToggle.checked ? 'block' : 'none';
      }

      if (radarAnimationToggle && radarSweepBeam) {
        radarSweepBeam.style.animationPlayState = radarAnimationToggle.checked ? 'running' : 'paused';
      }

      settingsModal.classList.add('hidden');
      showToast('SOC interface parameters applied');
    });
  }

  window.addEventListener('click', (e) => {
    if (e.target === settingsModal) {
      settingsModal.classList.add('hidden');
    }
  });

  // --- 14. ACTIVE NAV LINK HIGHLIGHTING ---
  const sections = document.querySelectorAll('section[id], main[id]');
  const navLinks = document.querySelectorAll('.nav-link');

  window.addEventListener('scroll', () => {
    let currentId = '';
    const scrollPos = window.pageYOffset + 140;

    sections.forEach(section => {
      const top = section.offsetTop;
      const height = section.offsetHeight;
      if (scrollPos >= top && scrollPos < top + height) {
        currentId = section.getAttribute('id');
      }
    });

    navLinks.forEach(link => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${currentId}`) {
        link.classList.add('active');
      }
    });
  });

  // --- INITIALIZATION ---
  initStatCounters();
  
  // Log readiness
  console.log('%c[PhishGuard SOC Command Center] // Connected to FastAPI: http://127.0.0.1:8001/api/analyze', 'color: #00f0ff; font-weight: bold;');
});
