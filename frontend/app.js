(() => {
    "use strict";

    const $  = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const dom = {
        targetUrl:       $("#targetUrl"),
        scanBtn:         $("#scanBtn"),
        urlHint:         $("#urlHint"),
        errorMsg:        $("#errorMsg"),

        scanInputCard:   $("#scanInputCard"),
        progressCard:    $("#progressCard"),
        resultsCard:     $("#resultsCard"),
        historyCard:     $("#historyCard"),
        errorCard:       $("#errorCard"),

        scanTarget:      $("#scanTarget"),
        spiderBar:       $("#spiderBar"),
        spiderPercent:   $("#spiderPercent"),
        activeBar:       $("#activeBar"),
        activePercent:   $("#activePercent"),
        scanPhaseLabel:  $("#scanPhaseLabel"),
        elapsedTimer:    $("#elapsedTimer"),

        statsGrid:       $("#statsGrid"),
        statHigh:        $("#statHigh"),
        statMedium:      $("#statMedium"),
        statLow:         $("#statLow"),
        statTotal:       $("#statTotal"),
        resultsSummary:  $("#resultsSummaryText"),
        filterTabs:      $("#filterTabs"),
        alertsList:      $("#alertsList"),

        // Severity chart
        chartHigh:       $("#chartHigh"),
        chartMed:        $("#chartMed"),
        chartLow:        $("#chartLow"),
        chartHighCount:  $("#chartHighCount"),
        chartMedCount:   $("#chartMedCount"),
        chartLowCount:   $("#chartLowCount"),

        newScanBtn:      $("#newScanBtn"),
        retryBtn:        $("#retryBtn"),
        stopBtn:         $("#stopBtn"),
        errorDetail:     $("#errorDetail"),
        hudClock:        $("#hudClock"),
        scanModes:       $("#scanModes"),
        navList:         $(".nav-list"),

        // Export
        exportJsonBtn:   $("#exportJsonBtn"),
        exportCsvBtn:    $("#exportCsvBtn"),

        // History
        historyList:     $("#historyList"),
    };

    let currentScanId = null;
    let pollTimer = null;
    let allAlerts = [];
    let selectedScanMode = "fast";
    let stoppingInProgress = false;
    let scanStartTime = null;
    let elapsedInterval = null;

    // Track which sections are "available"
    const sectionAvailability = {
        scanInputCard: true,
        progressCard: false,
        resultsCard: false,
        historyCard: true,
        errorCard: false,
    };

    const API_BASE = window.location.origin;
    const POLL_INTERVAL_MS = 1200;
    const POLL_INTERVAL_FAST_MS = 500;

    // Map section IDs to their cards
    const sectionCards = {
        scanInputCard: dom.scanInputCard,
        progressCard:  dom.progressCard,
        resultsCard:   dom.resultsCard,
        historyCard:   dom.historyCard,
        errorCard:     dom.errorCard,
    };

    function updateClock() {
        const now = new Date();
        const h = String(now.getHours()).padStart(2, "0");
        const m = String(now.getMinutes()).padStart(2, "0");
        dom.hudClock.textContent = `${h}:${m}`;
    }
    updateClock();
    setInterval(updateClock, 1000);

    // ------------------------------------------------------------------
    // Elapsed timer
    // ------------------------------------------------------------------
    function startElapsedTimer() {
        scanStartTime = Date.now();
        updateElapsed();
        if (elapsedInterval) clearInterval(elapsedInterval);
        elapsedInterval = setInterval(updateElapsed, 1000);
    }

    function stopElapsedTimer() {
        if (elapsedInterval) {
            clearInterval(elapsedInterval);
            elapsedInterval = null;
        }
    }

    function updateElapsed() {
        if (!scanStartTime) return;
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        const mins = Math.floor(elapsed / 60);
        const secs = String(elapsed % 60).padStart(2, "0");
        dom.elapsedTimer.textContent = `Elapsed: ${mins}:${secs}`;
    }

    // ------------------------------------------------------------------
    // TOC navigation
    // ------------------------------------------------------------------
    function setNavActive(sectionId) {
        $$(".nav-link").forEach((link) => {
            link.classList.remove("nav-link--active");
        });
        const activeLink = $(`.nav-link[data-target="${sectionId}"]`);
        if (activeLink) {
            activeLink.classList.add("nav-link--active");
        }
    }

    function enableNavLink(sectionId) {
        const link = $(`.nav-link[data-target="${sectionId}"]`);
        if (link) {
            link.classList.remove("nav-link--disabled");
            sectionAvailability[sectionId] = true;
        }
    }

    function disableNavLink(sectionId) {
        const link = $(`.nav-link[data-target="${sectionId}"]`);
        if (link) {
            link.classList.add("nav-link--disabled");
            sectionAvailability[sectionId] = false;
        }
    }

    function resetNavLinks() {
        enableNavLink("scanInputCard");
        enableNavLink("historyCard");
        disableNavLink("progressCard");
        disableNavLink("resultsCard");
        disableNavLink("errorCard");
    }

    function handleNavClick(e) {
        const link = e.target.closest(".nav-link");
        if (!link) return;
        e.preventDefault();
        if (link.classList.contains("nav-link--disabled")) return;

        const targetId = link.dataset.target;
        const card = sectionCards[targetId];
        if (!card) return;

        showCard(card);
        setNavActive(targetId);
    }

    // ------------------------------------------------------------------
    // Card visibility
    // ------------------------------------------------------------------
    function showCard(cardEl) {
        [dom.scanInputCard, dom.progressCard, dom.resultsCard, dom.historyCard, dom.errorCard]
            .forEach((c) => c.classList.add("hidden"));
        cardEl.classList.remove("hidden");
        cardEl.style.animation = "none";
        void cardEl.offsetHeight;
        cardEl.style.animation = "";

        if (cardEl === dom.progressCard) {
            dom.stopBtn.classList.remove("hidden");
        } else {
            dom.stopBtn.classList.add("hidden");
        }

        // Update nav active state to match the shown card
        for (const [id, el] of Object.entries(sectionCards)) {
            if (el === cardEl) {
                setNavActive(id);
                break;
            }
        }
    }

    function setProgress(barEl, percentEl, value) {
        const v = Math.min(100, Math.max(0, value));
        barEl.style.width = v + "%";
        barEl.setAttribute("aria-valuenow", v);
        percentEl.textContent = v + "%";
    }

    function setPhaseLabel(phase) {
        const labels = {
            idle:        "Initializing scanner…",
            spider:      "Spider crawling target site…",
            active_scan: "Running active vulnerability scan…",
            complete:    "Scan completed successfully",
            stopped:     "Scan stopped by user",
            error:       "Scan encountered an error",
        };
        const text = labels[phase] || labels.idle;
        const dot = dom.scanPhaseLabel.querySelector(".phase-status__dot");
        dom.scanPhaseLabel.querySelector("span:last-child").textContent = text;

        if (phase === "complete") {
            dot.style.background = "var(--color-success)";
            dot.style.animation = "none";
        } else if (phase === "error") {
            dot.style.background = "var(--color-risk-high)";
            dot.style.animation = "none";
        } else if (phase === "stopped") {
            dot.style.background = "var(--color-risk-med)";
            dot.style.animation = "none";
        } else {
            dot.style.background = "var(--color-accent)";
            dot.style.animation = "";
        }
    }

    function isValidUrl(str) {
        try {
            const url = new URL(str);
            return url.protocol === "http:" || url.protocol === "https:";
        } catch {
            return false;
        }
    }

    async function apiPost(path, body) {
        const res = await fetch(API_BASE + path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Request failed (${res.status})`);
        }
        return res.json();
    }

    async function apiGet(path) {
        const res = await fetch(API_BASE + path);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Request failed (${res.status})`);
        }
        return res.json();
    }

    // ------------------------------------------------------------------
    // Scan lifecycle
    // ------------------------------------------------------------------
    async function startScan() {
        const url = dom.targetUrl.value.trim();

        dom.errorMsg.textContent = "";
        if (!url) {
            dom.errorMsg.textContent = "Target URL is required";
            dom.targetUrl.focus();
            return;
        }
        if (!isValidUrl(url)) {
            dom.errorMsg.textContent = "Invalid URL — use http:// or https:// (e.g. http://192.168.1.10:8080)";
            dom.targetUrl.focus();
            return;
        }

        dom.scanBtn.classList.add("loading");
        stoppingInProgress = false;

        try {
            const data = await apiPost("/api/scan", { target_url: url, scan_mode: selectedScanMode });
            currentScanId = data.scan_id;

            setProgress(dom.spiderBar, dom.spiderPercent, 0);
            setProgress(dom.activeBar, dom.activePercent, 0);
            setPhaseLabel("idle");
            dom.scanTarget.textContent = url;

            // Reset stop button
            dom.stopBtn.disabled = false;
            dom.stopBtn.innerHTML = `<svg class="btn__icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="10" height="10" rx="2"/></svg> Stop Scan`;

            // Enable Progress in nav, disable Results/Errors
            enableNavLink("progressCard");
            disableNavLink("resultsCard");
            disableNavLink("errorCard");

            showCard(dom.progressCard);
            startElapsedTimer();
            beginPolling();
        } catch (err) {
            dom.errorMsg.textContent = err.message;
        } finally {
            dom.scanBtn.classList.remove("loading");
        }
    }

    function beginPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(pollStatus, POLL_INTERVAL_MS);
    }

    function beginFastPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(pollStatus, POLL_INTERVAL_FAST_MS);
    }

    async function pollStatus() {
        if (!currentScanId) return;

        try {
            const status = await apiGet(`/api/status/${currentScanId}`);

            setProgress(dom.spiderBar, dom.spiderPercent, status.spider_progress);
            setProgress(dom.activeBar, dom.activePercent, status.active_scan_progress);
            setPhaseLabel(status.phase);

            if (status.phase === "complete") {
                clearInterval(pollTimer);
                pollTimer = null;
                stopElapsedTimer();
                await showResults();
            } else if (status.phase === "stopped") {
                clearInterval(pollTimer);
                pollTimer = null;
                stopElapsedTimer();
                dom.stopBtn.classList.add("hidden");
                stoppingInProgress = false;
                setPhaseLabel("stopped");
                await showResults();
            } else if (status.phase === "error") {
                clearInterval(pollTimer);
                pollTimer = null;
                stopElapsedTimer();
                showError(status.error || "An unknown error occurred during the scan.");
            }
        } catch (err) {
            console.error("Polling error:", err);
        }
    }

    async function showResults() {
        try {
            const data = await apiGet(`/api/results/${currentScanId}`);

            animateCounter(dom.statHigh, data.summary.High || 0);
            animateCounter(dom.statMedium, data.summary.Medium || 0);
            animateCounter(dom.statLow, data.summary.Low || 0);
            animateCounter(dom.statTotal, data.total_alerts || 0);
            dom.resultsSummary.textContent =
                `${data.total_alerts} vulnerabilities detected in ${data.target_url}`;

            // Update severity chart
            updateSeverityChart(data.summary);

            allAlerts = data.alerts || [];
            renderAlerts(allAlerts);
            resetFilterTabs();

            // Enable Results in nav
            enableNavLink("resultsCard");

            showCard(dom.resultsCard);

            // Refresh history
            loadHistory();
        } catch (err) {
            showError(err.message);
        }
    }

    function updateSeverityChart(summary) {
        const high = summary.High || 0;
        const med = summary.Medium || 0;
        const low = summary.Low || 0;
        const total = high + med + low;

        dom.chartHighCount.textContent = high;
        dom.chartMedCount.textContent = med;
        dom.chartLowCount.textContent = low;

        if (total === 0) {
            dom.chartHigh.style.flex = "0";
            dom.chartMed.style.flex = "0";
            dom.chartLow.style.flex = "0";
            return;
        }

        // Use setTimeout to trigger CSS transition
        requestAnimationFrame(() => {
            dom.chartHigh.style.flex = String(high || 0.001);
            dom.chartMed.style.flex = String(med || 0.001);
            dom.chartLow.style.flex = String(low || 0.001);
        });
    }

    function showError(message) {
        dom.errorDetail.textContent = message;

        // Enable Errors in nav
        enableNavLink("errorCard");

        showCard(dom.errorCard);
    }

    function resetScan() {
        currentScanId = null;
        allAlerts = [];
        stoppingInProgress = false;
        dom.targetUrl.value = "";
        dom.errorMsg.textContent = "";
        selectedScanMode = "fast";
        $$(".mode-card").forEach((m) => m.classList.remove("mode-card--active"));
        $(".mode-card[data-mode='fast']").classList.add("mode-card--active");

        // Reset nav — Scan and History available
        resetNavLinks();

        showCard(dom.scanInputCard);
        dom.targetUrl.focus();
    }

    function handleModeSelect(e) {
        const modeCard = e.target.closest(".mode-card");
        if (!modeCard) return;
        const mode = modeCard.dataset.mode;
        if (!mode) return;

        selectedScanMode = mode;
        $$(".mode-card").forEach((m) => m.classList.remove("mode-card--active"));
        modeCard.classList.add("mode-card--active");
    }

    function animateCounter(el, target) {
        const duration = 600;
        const start = performance.now();

        function step(now) {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(target * eased);
            if (progress < 1) requestAnimationFrame(step);
        }

        requestAnimationFrame(step);
    }

    function renderAlerts(alerts) {
        if (!alerts.length) {
            dom.alertsList.innerHTML = `
                <div class="no-results">
                    <svg class="no-results__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    <p class="no-results__text">No vulnerabilities found for this filter</p>
                </div>`;
            return;
        }

        dom.alertsList.innerHTML = alerts.map((a, i) => {
            const urls = a.affected_urls || (a.url ? [a.url] : []);
            const urlCount = urls.length;
            let urlBlock = "";

            if (urlCount === 0) {
                urlBlock = "";
            } else if (urlCount === 1) {
                urlBlock = detailBlock("URL", urls[0], "url");
            } else {
                const urlList = urls.map(u => `<div class="affected-url">${escapeHtml(u)}</div>`).join("");
                urlBlock = `
                    <div class="alert-detail">
                        <div class="alert-detail__label">Affected URLs <span class="affected-url-count">${urlCount}</span></div>
                        <div class="alert-detail__value alert-detail__value--url-list">
                            <div class="affected-urls-preview">${escapeHtml(urls[0])}</div>
                            <details class="affected-urls-details">
                                <summary class="affected-urls-toggle">Show all ${urlCount} URLs</summary>
                                <div class="affected-urls-list">${urlList}</div>
                            </details>
                        </div>
                    </div>`;
            }

            return `
            <div class="alert-item" data-index="${i}">
                <div class="alert-item__header" role="button" tabindex="0" aria-expanded="false">
                    <span class="alert-item__badge alert-item__badge--${a.risk}">${a.risk}</span>
                    <span class="alert-item__name">${escapeHtml(a.name)}</span>
                    ${urlCount > 1 ? `<span class="alert-item__url-count">${urlCount} URLs</span>` : ""}
                    ${a.owasp_code ? `<span class="alert-item__owasp">${escapeHtml(a.owasp_code)}</span>` : ""}
                    <svg class="alert-item__chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
                </div>
                <div class="alert-item__body">
                    ${urlBlock}
                    ${detailBlock("Description",  a.description, "")}
                    ${detailBlock("Solution",     a.solution,    "")}
                    ${a.owasp_category ? detailBlock("OWASP Top 10", `${a.owasp_code}: ${a.owasp_category}`, "") : ""}
                    ${a.cwe_link ? detailBlock("CWE ID", `<a href="${escapeHtml(a.cwe_link)}" target="_blank" rel="noopener noreferrer">CWE-${escapeHtml(a.cweid)}</a>`, "link") : detailBlock("CWE ID", a.cweid, "")}
                    ${detailBlock("Confidence",   a.confidence,  "")}
                    ${detailBlock("Parameter",    a.param,       "")}
                    ${detailBlock("Evidence",     a.evidence,    "")}
                    ${detailBlock("Reference",    a.reference,   "")}
                </div>
            </div>`;
        }).join("");
    }

    function detailBlock(label, value, type) {
        if (!value) return "";
        const cls = type === "url" ? " alert-detail__value--url" : type === "link" ? " alert-detail__value--link" : "";
        return `
            <div class="alert-detail">
                <div class="alert-detail__label">${label}</div>
                <div class="alert-detail__value${cls}">${type === "link" ? value : escapeHtml(value)}</div>
            </div>`;
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    function resetFilterTabs() {
        $$(".filter-btn").forEach((t) => t.classList.remove("active"));
        $(".filter-btn[data-filter='all']").classList.add("active");
    }

    function handleFilter(e) {
        const tab = e.target.closest(".filter-btn");
        if (!tab) return;

        $$(".filter-btn").forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");

        const filter = tab.dataset.filter;
        const filtered = filter === "all"
            ? allAlerts
            : allAlerts.filter((a) => a.risk === filter);
        renderAlerts(filtered);
    }

    function handleAlertToggle(e) {
        const header = e.target.closest(".alert-item__header");
        if (!header) return;
        const item = header.closest(".alert-item");
        item.classList.toggle("open");
        header.setAttribute("aria-expanded", item.classList.contains("open"));
    }

    // ------------------------------------------------------------------
    // History
    // ------------------------------------------------------------------
    async function loadHistory() {
        try {
            const history = await apiGet("/api/history");
            renderHistory(history);
        } catch (err) {
            console.error("Failed to load history:", err);
        }
    }

    function renderHistory(entries) {
        if (!entries || entries.length === 0) {
            dom.historyList.innerHTML = `
                <div class="history-empty">
                    <p>No scans yet. Start a scan to see history here.</p>
                </div>`;
            return;
        }

        dom.historyList.innerHTML = entries.map((entry) => {
            const statusClass = entry.phase === "complete" ? "complete" :
                                entry.phase === "stopped" ? "stopped" :
                                entry.phase === "error" ? "error" : "running";
            const date = new Date(entry.started_at * 1000);
            const timeStr = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
            const dateStr = date.toLocaleDateString([], { month: "short", day: "numeric" });

            return `
                <div class="history-item" data-scan-id="${entry.scan_id}">
                    <span class="history-item__status history-item__status--${statusClass}"></span>
                    <div class="history-item__info">
                        <div class="history-item__url">${escapeHtml(entry.target_url)}</div>
                        <div class="history-item__meta">
                            <span>${entry.scan_mode}</span>
                            <span>${dateStr} ${timeStr}</span>
                            <span>${entry.phase}</span>
                        </div>
                    </div>
                    <div class="history-item__badges">
                        ${entry.alert_summary.High ? `<span class="history-badge history-badge--high">${entry.alert_summary.High}H</span>` : ""}
                        ${entry.alert_summary.Medium ? `<span class="history-badge history-badge--med">${entry.alert_summary.Medium}M</span>` : ""}
                        ${entry.alert_summary.Low ? `<span class="history-badge history-badge--low">${entry.alert_summary.Low}L</span>` : ""}
                    </div>
                </div>`;
        }).join("");
    }

    function handleHistoryClick(e) {
        const item = e.target.closest(".history-item");
        if (!item) return;
        const scanId = item.dataset.scanId;
        if (!scanId) return;

        // Load results for this scan
        currentScanId = scanId;
        showResults();
    }

    // ------------------------------------------------------------------
    // Export
    // ------------------------------------------------------------------
    function exportResults(format) {
        if (!currentScanId) return;
        const url = `${API_BASE}/api/export/${currentScanId}?format=${format}`;
        window.open(url, "_blank");
    }

    // ------------------------------------------------------------------
    // Event bindings
    // ------------------------------------------------------------------
    dom.scanBtn.addEventListener("click", startScan);

    dom.targetUrl.addEventListener("keydown", (e) => {
        if (e.key === "Enter") startScan();
    });

    dom.stopBtn.addEventListener("click", async () => {
        if (!currentScanId || stoppingInProgress) return;
        stoppingInProgress = true;
        dom.stopBtn.disabled = true;
        dom.stopBtn.innerHTML = `<svg class="btn__icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="10" height="10" rx="2"/></svg> Stopping…`;
        try {
            await apiPost(`/api/stop/${currentScanId}`, {});
            // Poll more aggressively to detect the stopped state faster
            beginFastPolling();
        } catch (err) {
            console.error("Stop error:", err);
            stoppingInProgress = false;
            dom.stopBtn.disabled = false;
            dom.stopBtn.innerHTML = `<svg class="btn__icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="10" height="10" rx="2"/></svg> Stop Scan`;
        }
    });

    dom.newScanBtn.addEventListener("click", resetScan);
    dom.retryBtn.addEventListener("click", resetScan);

    dom.filterTabs.addEventListener("click", handleFilter);
    dom.alertsList.addEventListener("click", handleAlertToggle);

    dom.alertsList.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
            const header = e.target.closest(".alert-item__header");
            if (header) {
                e.preventDefault();
                handleAlertToggle(e);
            }
        }
    });

    dom.scanModes.addEventListener("click", handleModeSelect);

    // Nav navigation click handler
    dom.navList.addEventListener("click", handleNavClick);

    // Export buttons
    dom.exportJsonBtn.addEventListener("click", () => exportResults("json"));
    dom.exportCsvBtn.addEventListener("click", () => exportResults("csv"));

    // History click handler
    dom.historyList.addEventListener("click", handleHistoryClick);

    // Load history on start
    loadHistory();

    dom.targetUrl.focus();
})();
