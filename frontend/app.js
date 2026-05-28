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
        errorCard:       $("#errorCard"),

        scanTarget:      $("#scanTarget"),
        spiderBar:       $("#spiderBar"),
        spiderPercent:   $("#spiderPercent"),
        activeBar:       $("#activeBar"),
        activePercent:   $("#activePercent"),
        scanPhaseLabel:  $("#scanPhaseLabel"),

        statsGrid:       $("#statsGrid"),
        statHigh:        $("#statHigh"),
        statMedium:      $("#statMedium"),
        statLow:         $("#statLow"),
        statTotal:       $("#statTotal"),
        resultsSummary:  $("#resultsSummaryText"),
        filterTabs:      $("#filterTabs"),
        alertsList:      $("#alertsList"),

        newScanBtn:      $("#newScanBtn"),
        retryBtn:        $("#retryBtn"),
        stopBtn:         $("#stopBtn"),
        errorDetail:     $("#errorDetail"),
        hudClock:        $("#hudClock"),
        scanModes:       $("#scanModes"),
        tocList:         $(".toc__list"),
    };

    let currentScanId = null;
    let pollTimer = null;
    let allAlerts = [];
    let selectedScanMode = "fast";
    let stoppingInProgress = false;

    // Track which sections are "available" (have been visited/have data)
    const sectionAvailability = {
        scanInputCard: true,
        progressCard: false,
        resultsCard: false,
        errorCard: false,
    };

    const API_BASE = window.location.origin;
    const POLL_INTERVAL_MS = 1500;

    // Map section IDs to their cards
    const sectionCards = {
        scanInputCard: dom.scanInputCard,
        progressCard:  dom.progressCard,
        resultsCard:   dom.resultsCard,
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
    // TOC navigation
    // ------------------------------------------------------------------
    function setTocActive(sectionId) {
        $$(".toc__link").forEach((link) => {
            link.classList.remove("toc__link--active");
        });
        const activeLink = $(`.toc__link[data-target="${sectionId}"]`);
        if (activeLink) {
            activeLink.classList.add("toc__link--active");
        }
    }

    function enableTocLink(sectionId) {
        const link = $(`.toc__link[data-target="${sectionId}"]`);
        if (link) {
            link.classList.remove("toc__link--disabled");
            sectionAvailability[sectionId] = true;
        }
    }

    function disableTocLink(sectionId) {
        const link = $(`.toc__link[data-target="${sectionId}"]`);
        if (link) {
            link.classList.add("toc__link--disabled");
            sectionAvailability[sectionId] = false;
        }
    }

    function resetTocLinks() {
        // Enable only Scan, disable the rest
        enableTocLink("scanInputCard");
        disableTocLink("progressCard");
        disableTocLink("resultsCard");
        disableTocLink("errorCard");
    }

    function handleTocClick(e) {
        const link = e.target.closest(".toc__link");
        if (!link) return;
        e.preventDefault();

        if (link.classList.contains("toc__link--disabled")) return;

        const targetId = link.dataset.target;
        const card = sectionCards[targetId];
        if (!card) return;

        showCard(card);
        setTocActive(targetId);
    }

    // ------------------------------------------------------------------
    // Card visibility
    // ------------------------------------------------------------------
    function showCard(cardEl) {
        [dom.scanInputCard, dom.progressCard, dom.resultsCard, dom.errorCard]
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

        // Update TOC active state to match the shown card
        for (const [id, el] of Object.entries(sectionCards)) {
            if (el === cardEl) {
                setTocActive(id);
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
            dot.style.background = "var(--success)";
        } else if (phase === "error") {
            dot.style.background = "var(--risk-high)";
        } else if (phase === "stopped") {
            dot.style.background = "var(--risk-med)";
        } else {
            dot.style.background = "var(--accent)";
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
            dom.errorMsg.textContent = "Invalid URL — include http:// or https://";
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

            // Enable Progress in TOC, disable Results/Errors
            enableTocLink("progressCard");
            disableTocLink("resultsCard");
            disableTocLink("errorCard");

            showCard(dom.progressCard);
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
                await showResults();
            } else if (status.phase === "stopped") {
                clearInterval(pollTimer);
                pollTimer = null;
                dom.stopBtn.classList.add("hidden");
                stoppingInProgress = false;
                setPhaseLabel("stopped");
                await showResults();
            } else if (status.phase === "error") {
                clearInterval(pollTimer);
                pollTimer = null;
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

            allAlerts = data.alerts || [];
            renderAlerts(allAlerts);
            resetFilterTabs();

            // Enable Results in TOC
            enableTocLink("resultsCard");

            showCard(dom.resultsCard);
        } catch (err) {
            showError(err.message);
        }
    }

    function showError(message) {
        dom.errorDetail.textContent = message;

        // Enable Errors in TOC
        enableTocLink("errorCard");

        showCard(dom.errorCard);
    }

    function resetScan() {
        currentScanId = null;
        allAlerts = [];
        stoppingInProgress = false;
        dom.targetUrl.value = "";
        dom.errorMsg.textContent = "";
        selectedScanMode = "fast";
        $$(".scan-mode").forEach((m) => m.classList.remove("scan-mode--selected"));
        $(".scan-mode[data-mode='fast']").classList.add("scan-mode--selected");

        // Reset TOC — only Scan is available
        resetTocLinks();

        showCard(dom.scanInputCard);
        dom.targetUrl.focus();
    }

    function handleModeSelect(e) {
        const modeCard = e.target.closest(".scan-mode");
        if (!modeCard) return;
        const mode = modeCard.dataset.mode;
        if (!mode) return;

        selectedScanMode = mode;
        $$(".scan-mode").forEach((m) => m.classList.remove("scan-mode--selected"));
        modeCard.classList.add("scan-mode--selected");
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

        dom.alertsList.innerHTML = alerts.map((a, i) => `
            <div class="alert-item" data-index="${i}">
                <div class="alert-item__header" role="button" tabindex="0" aria-expanded="false">
                    <span class="alert-item__badge alert-item__badge--${a.risk}">${a.risk}</span>
                    <span class="alert-item__name">${escapeHtml(a.name)}</span>
                    <svg class="alert-item__chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
                </div>
                <div class="alert-item__body">
                    ${detailBlock("URL",          a.url,         true)}
                    ${detailBlock("Description",  a.description, false)}
                    ${detailBlock("Solution",     a.solution,    false)}
                    ${detailBlock("Confidence",   a.confidence,  false)}
                    ${detailBlock("Parameter",    a.param,       false)}
                    ${detailBlock("Evidence",     a.evidence,    false)}
                    ${detailBlock("CWE ID",       a.cweid,       false)}
                    ${detailBlock("Reference",    a.reference,   false)}
                </div>
            </div>
        `).join("");
    }

    function detailBlock(label, value, isUrl) {
        if (!value) return "";
        const cls = isUrl ? " alert-detail__value--url" : "";
        return `
            <div class="alert-detail">
                <div class="alert-detail__label">${label}</div>
                <div class="alert-detail__value${cls}">${escapeHtml(value)}</div>
            </div>`;
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    function resetFilterTabs() {
        $$(".filter").forEach((t) => t.classList.remove("active"));
        $(".filter[data-filter='all']").classList.add("active");
    }

    function handleFilter(e) {
        const tab = e.target.closest(".filter");
        if (!tab) return;

        $$(".filter").forEach((t) => t.classList.remove("active"));
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
        dom.stopBtn.textContent = "Stopping…";
        try {
            await apiPost(`/api/stop/${currentScanId}`, {});
            // Immediately poll once to get the stopped state faster
            setTimeout(pollStatus, 300);
        } catch (err) {
            console.error("Stop error:", err);
            stoppingInProgress = false;
            dom.stopBtn.disabled = false;
            dom.stopBtn.textContent = "Stop scan";
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

    // TOC navigation click handler
    dom.tocList.addEventListener("click", handleTocClick);

    dom.targetUrl.focus();
})();
