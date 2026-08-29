/**
 * SecureVault Dashboard Charts & Visualizations
 */

document.addEventListener('DOMContentLoaded', () => {
    // Only run if on dashboard page with chart canvases
    const vulnChartCanvas = document.getElementById('vulnDistributionChart');
    const incidentTimelineCanvas = document.getElementById('incidentTimelineChart');

    if (!vulnChartCanvas && !incidentTimelineCanvas) return;

    // Fetch live metrics
    fetch('/api/metrics')
        .then(res => res.json())
        .then(data => {
            if (vulnChartCanvas) {
                initVulnChart(vulnChartCanvas, data.vulnerabilities);
            }
            if (incidentTimelineCanvas) {
                initIncidentChart(incidentTimelineCanvas, data.incidents, data.vault_categories);
            }
        })
        .catch(err => console.error('Error loading chart metrics:', err));
});

function initVulnChart(canvas, vulns) {
    const ctx = canvas.getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [vulns.critical || 0, vulns.high || 0, vulns.medium || 0, vulns.low || 0],
                backgroundColor: [
                    '#ef4444', // Critical red
                    '#f97316', // High orange
                    '#f59e0b', // Medium amber
                    '#10b981'  // Low emerald
                ],
                borderColor: '#0f172a',
                borderWidth: 3,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Inter', size: 12 },
                        padding: 16
                    }
                }
            },
            cutout: '70%'
        }
    });
}

function initIncidentChart(canvas, incidents, vaultCategories) {
    const ctx = canvas.getContext('2d');
    
    const catLabels = Object.keys(vaultCategories || {});
    const catValues = Object.values(vaultCategories || {});

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: catLabels.length ? catLabels : ['API Key', 'Database', 'SSH Key', 'Cloud', 'SSL', 'Tokens'],
            datasets: [{
                label: 'Protected Credentials',
                data: catValues.length ? catValues : [2, 1, 1, 1, 1, 1],
                backgroundColor: 'rgba(0, 242, 254, 0.65)',
                borderColor: '#00f2fe',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', stepSize: 1 }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}
