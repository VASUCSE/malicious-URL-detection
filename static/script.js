/**
 * Malicious URL Detection System - Client Engine
 * Handles REST API communication, Chart.js visualizations,
 * DOM updates, input validation, and interactive security telemetry.
 */

let threatChart = null;

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    initChart();
    loadDashboardStats();
    loadScanHistory();

    // Clear error banner on input edit
    const urlInput = document.getElementById("urlInput");
    if (urlInput) {
        urlInput.addEventListener("input", () => {
            clearInputError();
        });
    }
});

/**
 * Initialize Chart.js Doughnut Chart with Cyber SOC Theme
 */
function initChart() {
    const ctx = document.getElementById("threatDoughnutChart");
    if (!ctx) return;

    threatChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Safe", "Suspicious", "Phishing", "Malicious"],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    "#10b981", // Safe (Emerald)
                    "#f59e0b", // Suspicious (Amber)
                    "#f97316", // Phishing (Orange)
                    "#ef4444"  // Malicious (Crimson)
                ],
                borderColor: "#0e1526",
                borderWidth: 3,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#94a3b8",
                        font: {
                            family: "'JetBrains Mono', monospace",
                            size: 11
                        },
                        padding: 14,
                        usePointStyle: true,
                        pointStyle: "circle"
                    }
                },
                tooltip: {
                    backgroundColor: "rgba(14, 21, 38, 0.95)",
                    titleColor: "#00f2fe",
                    bodyColor: "#f8fafc",
                    borderColor: "rgba(0, 242, 254, 0.3)",
                    borderWidth: 1,
                    padding: 10,
                    boxPadding: 6,
                    callbacks: {
                        label: function (context) {
                            const label = context.label || "";
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                            return ` ${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: "70%"
        }
    });
}

/**
 * Fetch and Render Aggregate Stats for KPI Cards and Chart
 */
async function loadDashboardStats() {
    try {
        const response = await fetch("/api/stats");
        const data = await response.json();
        if (data.success && data.stats) {
            updateDashboardMetrics(data.stats);
        }
    } catch (err) {
        console.error("Failed to load statistics:", err);
    }
}

/**
 * Update UI metric cards and Doughnut Chart
 */
function updateDashboardMetrics(stats) {
    const totalElem = document.getElementById("statTotalScans");
    const safeElem = document.getElementById("statSafeScans");
    const safePctElem = document.getElementById("statSafePercent");
    const suspElem = document.getElementById("statSuspiciousScans");
    const suspPctElem = document.getElementById("statSuspiciousPercent");
    const threatElem = document.getElementById("statThreatScans");
    const threatPctElem = document.getElementById("statThreatPercent");

    if (totalElem) totalElem.textContent = stats.total_analyzed;
    if (safeElem) safeElem.textContent = stats.safe_count;
    if (safePctElem) safePctElem.textContent = `${stats.safe_percentage}% of total`;

    if (suspElem) suspElem.textContent = stats.suspicious_count;
    if (suspPctElem) suspPctElem.textContent = `${stats.suspicious_percentage}% of total`;

    if (threatElem) threatElem.textContent = stats.threat_count;
    if (threatPctElem) threatPctElem.textContent = `${stats.threat_percentage}% threat rate`;

    if (threatChart && stats.distribution) {
        threatChart.data.datasets[0].data = [
            stats.distribution.Safe || 0,
            stats.distribution.Suspicious || 0,
            stats.distribution.Phishing || 0,
            stats.distribution.Malicious || 0
        ];
        threatChart.update();
    }
}

/**
 * Fetch and Render Scan History from SQLite
 */
async function loadScanHistory() {
    const tbody = document.getElementById("historyBody");
    if (!tbody) return;

    try {
        const response = await fetch("/api/history?limit=15");
        const data = await response.json();

        if (!data.success || !data.history || data.history.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center">No scans recorded yet. Enter a URL above to inspect.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.history.map(item => {
            const badgeClass = `badge-${item.category.toLowerCase()}`;
            const riskColor = getRiskColor(item.risk_score);
            const shortUrl = escapeHtml(item.url);
            const timeStr = item.timestamp ? (item.timestamp.split(" ")[1] || item.timestamp) : "";

            return `
                <tr onclick="setSampleUrl('${escapeForAttr(item.url)}')" style="cursor: pointer;" title="Click to inspect this URL">
                    <td class="history-url-cell" title="${escapeHtml(item.url)}">${shortUrl}</td>
                    <td><span class="history-badge ${badgeClass}">${escapeHtml(item.category)}</span></td>
                    <td class="history-risk" style="color: ${riskColor};">${item.risk_score}%</td>
                    <td>${escapeHtml(timeStr)}</td>
                </tr>
            `;
        }).join("");

    } catch (err) {
        console.error("Failed to load scan history:", err);
        tbody.innerHTML = `<tr><td colspan="4" class="text-center" style="color: #ef4444;">Failed to load history log</td></tr>`;
    }
}

/**
 * Validate input before sending to server
 */
function validateUrlInput(rawUrl) {
    if (!rawUrl || rawUrl.trim() === "") {
        return "Please enter a URL to inspect.";
    }

    if (rawUrl.length > 2048) {
        return "URL exceeds maximum permissible length (2048 characters).";
    }

    const lower = rawUrl.toLowerCase().trim();
    const unsupported = [
        "javascript:", "data:", "file:", "blob:", "vbscript:",
        "about:", "chrome:", "intent:", "ftp:"
    ];
    for (const scheme of unsupported) {
        if (lower.startsWith(scheme)) {
            return `Unsupported or dangerous scheme '${scheme}'. Only web URLs (HTTP/HTTPS or domain names) are supported for security inspection.`;
        }
    }

    return null;
}

/**
 * Display inline validation error
 */
function showInputError(message) {
    const banner = document.getElementById("inputValidationError");
    const textElem = document.getElementById("inputErrorMessage");
    if (banner && textElem) {
        textElem.textContent = message;
        banner.classList.remove("hidden");
    }
}

/**
 * Clear inline validation error
 */
function clearInputError() {
    const banner = document.getElementById("inputValidationError");
    if (banner) {
        banner.classList.add("hidden");
    }
}

/**
 * Submit URL for Safe Isolated Analysis
 */
async function analyzeUrl() {
    const input = document.getElementById("urlInput");
    const rawUrl = input.value.trim();

    // Client-side validation
    const validationError = validateUrlInput(rawUrl);
    if (validationError) {
        showInputError(validationError);
        input.focus();
        return;
    }
    clearInputError();

    const btn = document.getElementById("btnAnalyze");
    const loader = document.getElementById("scanLoader");
    const resultsPanel = document.getElementById("resultsContainer");

    // UI Busy State
    btn.disabled = true;
    loader.classList.remove("hidden");
    resultsPanel.classList.add("hidden");

    // Cycle animated phase text
    const phases = [
        "Extracting Lexical Vectors...",
        "Evaluating Entropy & Obfuscation...",
        "Executing Random Forest Inference...",
        "Generating Risk Assessment..."
    ];
    let phaseIdx = 0;
    const phaseInterval = setInterval(() => {
        phaseIdx = (phaseIdx + 1) % phases.length;
        const phaseElem = document.getElementById("loaderPhaseText");
        if (phaseElem) phaseElem.textContent = phases[phaseIdx];
    }, 280);

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: rawUrl })
        });

        clearInterval(phaseInterval);
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Security inspection failed.");
        }

        renderAnalysisResults(data);
        loadDashboardStats();
        loadScanHistory();

    } catch (error) {
        clearInterval(phaseInterval);
        showInputError(error.message);
        showToast(`Scan Error: ${error.message}`);
    } finally {
        btn.disabled = false;
        loader.classList.add("hidden");
    }
}

/**
 * Render Detailed Verdict, Probability Bars, Red Flags, and Features Matrix
 */
function renderAnalysisResults(data) {
    const panel = document.getElementById("resultsContainer");
    panel.classList.remove("hidden");

    // Timestamp
    const tsElem = document.getElementById("resTimestamp");
    if (tsElem) tsElem.textContent = new Date().toLocaleTimeString();

    // Verdict Hero Styling and Class State
    const hero = document.getElementById("verdictHero");
    const cat = data.category.toLowerCase();
    hero.className = `verdict-hero ${cat}-state`;

    // Verdict Category & Level
    const badge = document.getElementById("resCategoryBadge");
    badge.className = `verdict-badge ${cat}`;
    badge.textContent = data.category.toUpperCase();

    document.getElementById("resRiskLevel").textContent = data.risk_level;
    document.getElementById("resAnalyzedUrl").textContent = data.url;

    // Verdict Icon
    const iconElem = document.getElementById("verdictIcon");
    if (data.category === "Safe") iconElem.textContent = "🛡️";
    else if (data.category === "Suspicious") iconElem.textContent = "⚠️";
    else if (data.category === "Phishing") iconElem.textContent = "🎣";
    else iconElem.textContent = "🚨"; // Malicious

    // Risk Meter Circle (Circumference for r=42 is ~264)
    const riskCircle = document.getElementById("riskMeterCircle");
    const riskScore = Math.min(100, Math.max(0, data.risk_score));
    const circumference = 264;
    const offset = circumference - (riskScore / 100 * circumference);

    riskCircle.style.strokeDashoffset = offset;
    const riskColor = getRiskColor(riskScore);
    riskCircle.style.stroke = riskColor;

    animateCounter("resRiskScore", riskScore);

    // Recommendation
    document.getElementById("resRecommendationText").textContent = data.recommendation;
    const recBox = document.getElementById("resRecommendationBox");
    recBox.style.borderLeftColor = riskColor;

    // Confidence & Probabilities
    document.getElementById("resConfidence").textContent = `${data.confidence}% Confidence`;

    const probs = data.probabilities || {};
    updateProbBar("probSafeBar", "probSafeVal", probs["Safe"] || 0);
    updateProbBar("probSuspiciousBar", "probSuspiciousVal", probs["Suspicious"] || 0);
    updateProbBar("probPhishingBar", "probPhishingVal", probs["Phishing"] || 0);
    updateProbBar("probMaliciousBar", "probMaliciousVal", probs["Malicious"] || 0);

    // Red Flags List
    const flagsList = document.getElementById("redFlagsList");
    const flagsCount = document.getElementById("redFlagsCount");
    const flags = data.red_flags || [];

    flagsCount.textContent = `${flags.length} Indicator${flags.length === 1 ? '' : 's'}`;

    if (flags.length === 0) {
        flagsList.innerHTML = `<li class="no-flags">No suspicious anomalies or security red flags detected. URL exhibits standard benign lexical structure.</li>`;
    } else {
        flagsList.innerHTML = flags.map(flag => `<li>${escapeHtml(flag)}</li>`).join("");
    }

    // Detailed Features Grid (18 structural features)
    const featuresGrid = document.getElementById("featuresGrid");
    const featObj = data.detailed_features || {};

    featuresGrid.innerHTML = Object.keys(featObj).map(key => {
        const item = featObj[key];
        const statusClass = `tag-${item.status}`;
        return `
            <div class="feature-box">
                <div class="feature-top">
                    <span class="feature-name">${escapeHtml(item.name)}</span>
                    <span class="feature-status-tag ${statusClass}">${escapeHtml(item.status)}</span>
                </div>
                <div class="feature-value">${escapeHtml(String(item.value))}</div>
                <div class="feature-desc">${escapeHtml(item.description)}</div>
            </div>
        `;
    }).join("");

    // Smooth scroll down to view results cleanly
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function updateProbBar(barId, valId, val) {
    const bar = document.getElementById(barId);
    const text = document.getElementById(valId);
    if (bar && text) {
        bar.style.width = `${val}%`;
        text.textContent = `${val}%`;
    }
}

function animateCounter(elementId, targetValue) {
    const elem = document.getElementById(elementId);
    if (!elem) return;

    let start = 0;
    const duration = 800;
    const startTime = performance.now();

    function update(time) {
        const elapsed = time - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const current = Math.round(start + (targetValue - start) * progress);
        elem.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            elem.textContent = targetValue;
        }
    }

    requestAnimationFrame(update);
}

function getRiskColor(score) {
    if (score <= 25) return "#10b981";       // Safe
    if (score <= 55) return "#f59e0b";       // Suspicious
    if (score <= 80) return "#f97316";       // Phishing
    return "#ef4444";                        // Malicious
}

function setSampleUrl(url) {
    const input = document.getElementById("urlInput");
    input.value = url;
    clearInputError();
    input.focus();
    analyzeUrl();
}

function clearInput() {
    const input = document.getElementById("urlInput");
    input.value = "";
    clearInputError();
    input.focus();
}

async function clearHistory() {
    if (!confirm("Are you sure you want to clear all URL scan history from the database?")) {
        return;
    }

    try {
        const res = await fetch("/api/clear-history", { method: "POST" });
        const data = await res.json();
        if (data.success) {
            showToast("Database scan history cleared.");
            loadScanHistory();
            loadDashboardStats();
        }
    } catch (err) {
        showToast("Failed to clear database history.");
    }
}

function showToast(message) {
    const toast = document.getElementById("toastNotification");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.remove("hidden");
    setTimeout(() => {
        toast.classList.add("hidden");
    }, 3500);
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function escapeForAttr(str) {
    if (!str) return "";
    return String(str).replace(/'/g, "\\'");
}
