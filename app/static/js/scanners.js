/**
 * SecureVault Security Scanner Suite Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Web Headers & SSL Scanner Form
    const headerForm = document.getElementById('headerScanForm');
    if (headerForm) {
        headerForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const targetUrl = document.getElementById('targetUrlInput').value.trim();
            if (!targetUrl) return;

            const btn = document.getElementById('scanSubmitBtn');
            const loading = document.getElementById('scanLoadingState');
            const resultsBox = document.getElementById('headerScanResults');

            btn.disabled = true;
            loading.classList.remove('d-none');
            resultsBox.classList.add('d-none');

            fetch('/scanners/api/scan-headers', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl })
            })
            .then(res => res.json())
            .then(data => {
                btn.disabled = false;
                loading.classList.add('d-none');
                resultsBox.classList.remove('d-none');

                renderHeaderScanResults(data.results);
            })
            .catch(err => {
                btn.disabled = false;
                loading.classList.add('d-none');
                alert('Scanner failed: ' + err);
            });
        });
    }

    // 2. Port Recon Form
    const portForm = document.getElementById('portScanForm');
    if (portForm) {
        portForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const host = document.getElementById('targetHostInput').value.trim();
            if (!host) return;

            const btn = document.getElementById('portScanBtn');
            const loading = document.getElementById('portScanLoading');
            const resultsBox = document.getElementById('portScanResults');

            btn.disabled = true;
            loading.classList.remove('d-none');
            resultsBox.classList.add('d-none');

            fetch('/scanners/api/scan-ports', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host: host })
            })
            .then(res => res.json())
            .then(data => {
                btn.disabled = false;
                loading.classList.add('d-none');
                resultsBox.classList.remove('d-none');

                renderPortScanResults(data.results);
            })
            .catch(err => {
                btn.disabled = false;
                loading.classList.add('d-none');
                alert('Port scan error: ' + err);
            });
        });
    }

    // 3. Password Entropy Live Analyzer
    const pwdInput = document.getElementById('entropyTestInput');
    if (pwdInput) {
        pwdInput.addEventListener('input', () => {
            const val = pwdInput.value;
            fetch('/scanners/api/password-entropy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: val })
            })
            .then(res => res.json())
            .then(data => {
                renderEntropyResults(data.analysis);
            });
        });
    }
});

function renderHeaderScanResults(results) {
    const gradeBadge = document.getElementById('resGradeBadge');
    const scoreVal = document.getElementById('resScoreVal');
    const targetDomain = document.getElementById('resTargetDomain');
    const passedList = document.getElementById('resPassedHeaders');
    const missingList = document.getElementById('resMissingHeaders');
    const sslDetails = document.getElementById('resSslDetails');

    if (gradeBadge) gradeBadge.textContent = results.grade || 'C';
    if (scoreVal) scoreVal.textContent = `${results.score || 0}/100 Security Score`;
    if (targetDomain) targetDomain.textContent = results.domain || results.url;

    // Passed headers
    if (passedList) {
        passedList.innerHTML = '';
        if (results.passed && results.passed.length > 0) {
            results.passed.forEach(item => {
                const li = document.createElement('li');
                li.className = 'list-group-item bg-transparent text-white border-bottom border-secondary d-flex justify-content-between align-items-start py-2';
                li.innerHTML = `
                    <div>
                        <div class="fw-bold text-info"><i class="bi bi-shield-check text-success me-1"></i> ${item.header}</div>
                        <small class="text-muted">${item.description}</small>
                    </div>
                    <span class="badge bg-success bg-opacity-25 text-success border border-success">ACTIVE</span>
                `;
                passedList.appendChild(li);
            });
        } else {
            passedList.innerHTML = '<div class="text-muted p-2">No recommended security headers detected.</div>';
        }
    }

    // Missing headers
    if (missingList) {
        missingList.innerHTML = '';
        if (results.missing_headers && results.missing_headers.length > 0) {
            results.missing_headers.forEach(item => {
                const li = document.createElement('li');
                li.className = 'list-group-item bg-transparent text-white border-bottom border-secondary d-flex justify-content-between align-items-start py-2';
                li.innerHTML = `
                    <div>
                        <div class="fw-bold text-warning"><i class="bi bi-exclamation-triangle text-warning me-1"></i> ${item.header}</div>
                        <small class="text-muted">${item.description}</small>
                    </div>
                    <span class="badge bg-danger bg-opacity-25 text-danger border border-danger">${item.risk}</span>
                `;
                missingList.appendChild(li);
            });
        } else {
            missingList.innerHTML = '<div class="text-success p-2"><i class="bi bi-check-all"></i> All standard security headers configured!</div>';
        }
    }

    // SSL Details
    if (sslDetails && results.ssl_info) {
        if (results.ssl_info.error) {
            sslDetails.innerHTML = `<div class="text-danger"><i class="bi bi-x-circle"></i> ${results.ssl_info.error}</div>`;
        } else {
            sslDetails.innerHTML = `
                <div class="row g-2 text-sm">
                    <div class="col-sm-6"><span class="text-muted">Subject / Domain:</span> <span class="fw-semibold text-white">${results.ssl_info.subject}</span></div>
                    <div class="col-sm-6"><span class="text-muted">Issuer:</span> <span class="fw-semibold text-white">${results.ssl_info.issuer}</span></div>
                    <div class="col-sm-6"><span class="text-muted">TLS Protocol:</span> <span class="badge bg-info bg-opacity-10 text-info border border-info">${results.ssl_info.tls_version}</span></div>
                    <div class="col-sm-6"><span class="text-muted">Validity:</span> <span class="badge bg-success bg-opacity-10 text-success border border-success">${results.ssl_info.days_remaining} days remaining</span></div>
                </div>
            `;
        }
    }
}

function renderPortScanResults(results) {
    const tableBody = document.getElementById('portResultsTableBody');
    if (!tableBody) return;

    tableBody.innerHTML = '';
    results.ports.forEach(p => {
        const tr = document.createElement('tr');
        const isOpen = p.status === 'Open';
        tr.innerHTML = `
            <td class="mono-text fw-bold text-white">${p.port}</td>
            <td><span class="badge bg-secondary bg-opacity-50 text-white">${p.service}</span></td>
            <td><span class="badge ${isOpen ? 'bg-danger bg-opacity-25 text-danger border border-danger' : 'bg-success bg-opacity-25 text-success border border-success'}">${p.status}</span></td>
            <td class="text-muted">${p.description}</td>
            <td class="mono-text text-dim">${p.latency_ms} ms</td>
        `;
        tableBody.appendChild(tr);
    });
}

function renderEntropyResults(analysis) {
    const entropyBar = document.getElementById('entropyProgressBar');
    const scoreVal = document.getElementById('entropyBitsVal');
    const strengthLabel = document.getElementById('entropyStrengthLabel');
    const feedbackList = document.getElementById('entropyFeedbackList');

    if (scoreVal) scoreVal.textContent = `${analysis.entropy} bits`;
    if (strengthLabel) strengthLabel.textContent = analysis.strength;

    if (entropyBar) {
        const pct = Math.min(100, Math.round((analysis.entropy / 100) * 100));
        entropyBar.style.width = `${pct}%`;
        entropyBar.className = 'progress-bar';
        if (analysis.score <= 1) entropyBar.classList.add('bg-danger');
        else if (analysis.score === 2) entropyBar.classList.add('bg-warning');
        else if (analysis.score === 3) entropyBar.classList.add('bg-info');
        else entropyBar.classList.add('bg-success');
    }

    if (feedbackList) {
        feedbackList.innerHTML = '';
        analysis.feedback.forEach(item => {
            const li = document.createElement('li');
            li.className = 'text-muted small mb-1';
            li.textContent = `• ${item}`;
            feedbackList.appendChild(li);
        });
    }
}
