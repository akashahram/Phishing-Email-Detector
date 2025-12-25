// SHADOW OPS - Enhanced JavaScript for New Layout
// Updated to work with redesigned HTML structure

/* ═══════════════════════════════════════════════════════════
   UTILITY FUNCTIONS
   ═══════════════════════════════════════════════════════════ */

function escapeHtml(s) {
  return String(s).replace(/[&<>"'`=\/]/g, function (ch) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;',
      '`': '&#x60;',
      '=': '&#x3D;'
    }[ch];
  });
}

function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

function animateValue(element, start, end, duration, suffix = '') {
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const value = start + (end - start) * easeOutCubic(progress);

    element.textContent = Math.round(value) + suffix;

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

/* ═══════════════════════════════════════════════════════════
   PROGRESS ANIMATIONS
   ═══════════════════════════════════════════════════════════ */

function showProgressSection() {
  const section = document.getElementById('progressSection');
  const results = document.getElementById('resultsSection');

  section.style.display = 'block';
  results.style.display = 'none';

  // Reset progress
  setProgress(0, 'Initializing scan...');
}

function hideProgressSection() {
  const section = document.getElementById('progressSection');
  section.style.display = 'none';
}

function showResultsSection() {
  const section = document.getElementById('resultsSection');
  section.style.display = 'block';
}

function setProgress(pct, text) {
  const fill = document.getElementById('progressFill');
  const textEl = document.getElementById('progressText');
  const percentage = document.getElementById('progressPercentage');

  fill.style.width = Math.min(100, pct) + '%';

  if (text) {
    textEl.innerText = text;
  }

  if (percentage) {
    percentage.innerText = Math.round(pct) + '%';
  }
}

async function animateProgress(duration = 400) {
  const start = performance.now();

  return new Promise(resolve => {
    function step(t) {
      const elapsed = t - start;
      const pct = Math.min(95, (elapsed / duration) * 100);
      const easedPct = easeOutCubic(pct / 100) * 100;

      setProgress(easedPct, `Analyzing... ${Math.round(easedPct)}%`);

      if (pct < 95) {
        requestAnimationFrame(step);
      } else {
        resolve();
      }
    }
    requestAnimationFrame(step);
  });
}

/* ═══════════════════════════════════════════════════════════
   RESULT DISPLAY FUNCTIONS
   ═══════════════════════════════════════════════════════════ */

function showResult(data) {
  const card = document.getElementById('resultCard');
  const icon = document.getElementById('resultIcon');
  const title = document.getElementById('resultTitle');
  const subtitle = document.getElementById('resultSubtitle');
  const probValue = document.getElementById('probabilityValue');
  const probFill = document.getElementById('probabilityFill');
  const reasonText = document.getElementById('reasonText');
  const scoresGrid = document.getElementById('scoresGrid');

  const prediction = data.prediction || 0;
  const probability = data.probability || 0;
  const probPercent = Math.round(probability * 100);

  // Update card class
  card.className = 'result-card active ' + (prediction === 1 ? 'phish' : 'safe');

  // Update icon and title
  if (prediction === 1) {
    icon.textContent = '⚠️';
    title.textContent = 'PHISHING DETECTED';
    subtitle.textContent = 'This email exhibits characteristics of a phishing attempt';
  } else {
    icon.textContent = '✓';
    title.textContent = 'SAFE EMAIL';
    subtitle.textContent = 'No significant threats detected in this email';
  }

  // Animate probability
  animateValue(probValue, 0, probPercent, 800, '%');

  // Animate probability bar
  setTimeout(() => {
    probFill.style.width = probPercent + '%';
  }, 100);

  // Update reason
  reasonText.textContent = data.reason || 'Analysis complete';

  // Update scores
  scoresGrid.innerHTML = `
    <div class="score-item">
      <div class="score-label">ML Score</div>
      <div class="score-value">${Math.round((data.ml_score || 0) * 100)}%</div>
    </div>
    <div class="score-item">
      <div class="score-label">URL Risk</div>
      <div class="score-value">${data.url_risk_score || 0}</div>
    </div>
    <div class="score-item">
      <div class="score-label">Forensics</div>
      <div class="score-value">${data.forensics_score || 0}</div>
    </div>
  `;

  // Show findings
  showFindings(data);

  // Show signals
  showSignals(data);
}

function showFindings(data) {
  const container = document.getElementById('findingsContainer');
  container.innerHTML = '';

  const allFindings = [
    ...(data.url_findings || []),
    ...(data.forensics_findings || [])
  ];

  if (allFindings.length === 0) return;

  // Group findings by category
  const categories = {
    'URL Intelligence': data.url_findings || [],
    'Email Forensics': data.forensics_findings || []
  };

  Object.entries(categories).forEach(([category, findings]) => {
    if (findings.length === 0) return;

    const section = document.createElement('div');
    section.className = 'findings-section';

    section.innerHTML = `
      <div class="findings-header">
        <span class="findings-icon">${category === 'URL Intelligence' ? '🔗' : '📧'}</span>
        <h4 class="findings-title">${category}</h4>
      </div>
      <div class="findings-list">
        ${findings.map(f => `
          <div class="finding-item ${f.severity || 'medium'}">
            <strong>${f.category || 'Detection'}:</strong> ${escapeHtml(f.message || f.description || '')}
          </div>
        `).join('')}
      </div>
    `;

    container.appendChild(section);
  });
}

function showSignals(data) {
  const grid = document.getElementById('signalsGrid');
  const signals = data.signals || {};

  if (Object.keys(signals).length === 0) {
    grid.innerHTML = '';
    return;
  }

  grid.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <div class="panel-icon">📊</div>
        <h3 class="panel-title">Detection Signals</h3>
      </div>
      <div class="signals-grid">
        ${Object.entries(signals).map(([key, value]) => `
          <div class="signal-item">
            <div class="signal-label">${key.replace(/_/g, ' ')}</div>
            <div class="signal-value">${value}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════
   SCAN FUNCTIONS
   ═══════════════════════════════════════════════════════════ */

async function scanText() {
  const text = document.getElementById("emailText").value;

  if (!text || text.trim().length < 5) {
    alert("⚠ Please paste email text first (at least a few words).");
    return;
  }

  // Show progress section
  showProgressSection();
  document.getElementById("serverStatus").innerText = "Scanning";

  // Animate progress
  await animateProgress(400);

  try {
    const res = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });

    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }

    const data = await res.json();

    if (data.error) {
      throw new Error(data.error);
    }

    // Complete progress
    setProgress(100, "Scan complete ✓");

    // Wait a moment then show results
    setTimeout(() => {
      hideProgressSection();
      showResultsSection();
      showResult(data);
      document.getElementById("serverStatus").innerText = "Ready";
    }, 500);

  } catch (error) {
    console.error('Scan error:', error);
    alert(`⚠ Scan failed: ${error.message}`);
    hideProgressSection();
    document.getElementById("serverStatus").innerText = "Ready";
  }
}

async function scanEML() {
  const fileInput = document.getElementById("emlFile");
  const f = fileInput.files[0];

  if (!f) {
    alert("⚠ Please choose a .eml file to scan.");
    return;
  }

  // Show progress section
  showProgressSection();
  document.getElementById("serverStatus").innerText = "Scanning .eml";

  // Animate progress
  await animateProgress(400);

  try {
    const fd = new FormData();
    fd.append('file', f);

    const res = await fetch('/scan_eml', {
      method: 'POST',
      body: fd
    });

    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }

    const data = await res.json();

    if (data.error) {
      throw new Error(data.error);
    }

    // Complete progress
    setProgress(100, "Scan complete ✓");

    // Wait a moment then show results
    setTimeout(() => {
      hideProgressSection();
      showResultsSection();
      showResult(data);

      // Show cleaned email text if available
      if (data.cleaned_text) {
        const cleanedContainer = document.getElementById("cleanedText");
        cleanedContainer.innerHTML = `
          <div class="panel">
            <div class="panel-header">
              <div class="panel-icon">📧</div>
              <h3 class="panel-title">Extracted Email Body</h3>
            </div>
            <div class="email-card">
              <div style="white-space: pre-wrap; color: var(--text-secondary);">
                ${escapeHtml(data.cleaned_text)}
              </div>
            </div>
          </div>
        `;
      }

      document.getElementById("serverStatus").innerText = "Ready";
    }, 500);

  } catch (error) {
    console.error('EML scan error:', error);
    alert(`⚠ EML scan failed: ${error.message}`);
    hideProgressSection();
    document.getElementById("serverStatus").innerText = "Ready";
  }
}

/* ═══════════════════════════════════════════════════════════
   INITIALIZATION
   ═══════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  // Add keyboard shortcut for quick scan (Ctrl+Enter)
  const emailTextArea = document.getElementById("emailText");
  if (emailTextArea) {
    emailTextArea.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        scanText();
      }
    });
  }

  // Update file input label when file is selected
  const fileInput = document.getElementById("emlFile");
  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      const label = document.querySelector('.file-text');
      if (e.target.files.length > 0) {
        label.textContent = e.target.files[0].name;
      } else {
        label.textContent = 'Choose file or drag here';
      }
    });
  }

  console.log('%c⚑ SHADOW OPS', 'color: #00d9ff; font-size: 20px; font-weight: bold;');
  console.log('%cEnterprise Phishing Detection System', 'color: #8892b0; font-size: 12px;');
  console.log('%cReady for analysis...', 'color: #00ff88;');
});
