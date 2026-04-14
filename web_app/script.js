const loadingContainer = document.getElementById('loadingContainer');
const loadingBar       = document.getElementById('loadingBar');
let progressInterval;

async function scan() {
    url_bar(0);

    let rawUrl = document.getElementById("url").value.trim();
    let error  = document.getElementById("error");

    clearInterval(progressInterval);
    loadingBar.style.width = '0%';
    error.innerHTML = "";

    if (rawUrl === "") {
        error.innerHTML = "INPUT THE URL YOU WANT TO SCAN";
        return;
    }

    // Auto-prepend scheme so new URL() doesn't throw on bare domains like google.com
    let url = rawUrl;
    if (!/^https?:\/\//i.test(url)) {
        url = "https://" + url;
    }

    // Validate
    try {
        const parsed = new URL(url);
        const host   = parsed.hostname;
        const isIp   = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
        if (!host.includes(".") && !isIp) throw new Error("invalid host");
    } catch {
        error.innerHTML = "INVALID URL FORMAT";
        return;
    }

    // ── Start loading bar ─────────────────────────────────────────────────
    error.innerHTML = "SCANNING TARGET...";
    loadingContainer.classList.remove('hidden');
    let progress = 0;
    progressInterval = setInterval(() => {
        progress += Math.random() * 10;
        if (progress > 90) progress = 90;
        loadingBar.style.width = `${progress}%`;
    }, 400);

    try {
        // ── POST to /analyze ──────────────────────────────────────────────
        const res = await fetch("http://127.0.0.1:8000/analyze", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ url }),
        });

        if (!res.ok) {
            const detail = await res.json().catch(() => ({ detail: res.statusText }));
            throw new Error(detail.detail || `Server error ${res.status}`);
        }

        const data = await res.json();

        // ── Loading bar → 100% ────────────────────────────────────────────
        clearInterval(progressInterval);
        loadingBar.style.width = "100%";

        setTimeout(() => {
            loadingContainer.classList.add('hidden');
            error.innerHTML = "";

            // ── Screenshot ────────────────────────────────────────────────
            const screenImg = document.getElementById('forensicScreenshot');
            if (screenImg && data.screenshot) {
                screenImg.src = data.screenshot + "?t=" + Date.now();
                screenImg.classList.remove('grayscale');
            }

            // ── DNS Recon link unlock ─────────────────────────────────────
            const dnsLink = document.getElementById('dnsReconLink');
            if (dnsLink) {
                dnsLink.classList.remove('text-white/30', 'pointer-events-none', 'cursor-not-allowed');
                dnsLink.classList.add('text-[#adaaaa]', 'hover:bg-[#1a1919]', 'cursor-pointer');
            }

            // ── Phishing gauge ────────────────────────────────────────────
            let proba;
            if (data.prediction === "phishing") {
                proba = data.probability * 100;
            } else {
                proba = (1 - data.probability) * 100;
            }
            url_bar(Math.round(proba));

            // ── Top-features bars ─────────────────────────────────────────
            const featureSlots = [
                { name: "feature1", prob: "prob_of_feat_1", bar: "feature_1_bar" },
                { name: "feature2", prob: "prob_of_feat_2", bar: "feature_2_bar" },
                { name: "feature3", prob: "prob_of_feat_3", bar: "feature_3_bar" },
                { name: "feature4", prob: "prob_of_feat_4", bar: "feature_4_bar" },
            ];
            const keys = Object.keys(data.top_features || {});
            featureSlots.forEach((slot, i) => {
                if (!keys[i]) return;
                const key = keys[i];
                const val = data.top_features[key];
                document.getElementById(slot.name).textContent = key;
                document.getElementById(slot.prob).textContent = Math.round(val) + "%";
                feature_bar(val, document.getElementById(slot.bar));
            });

        }, 400);

        // ── Fire-and-forget DNS recon (saves to localStorage for dns page) 
        fetch("http://127.0.0.1:8000/DnsRec", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ url }),
        })
        .then(r => r.json())
        .then(d => {
            localStorage.setItem('dns_results', JSON.stringify(d));
            console.log("DNS recon saved:", d);
            // If dns_recon page is open in the same tab, storage event won't fire —
            // call its refresh function directly if available
            if (window.refreshDnsRecon) window.refreshDnsRecon();
        })
        .catch(e => console.warn("DNS recon failed (non-critical):", e));

    } catch (err) {
        console.error("Scan error:", err);
        clearInterval(progressInterval);
        loadingContainer.classList.add('hidden');
        error.innerHTML = "SCAN FAILED: " + (err.message || "Unknown error");
    }
}

// ── Circular gauge ────────────────────────────────────────────────────────
function url_bar(value) {
    const circle = document.getElementById("progressCircle");
    const text   = document.getElementById("percentText");
    const status = document.getElementById("statusText");

    const circumference = 552.92;
    circle.style.strokeDashoffset = circumference - (value / 100) * circumference;
    text.innerText = value + "%";

    if (value > 70) {
        status.innerText        = "MALICIOUS";
        circle.style.color      = "#ea0703";
        circle.style.filter     = "drop-shadow(0 0 8px #ea0703)";
    } else if (value > 40) {
        status.innerText        = "SUSPICIOUS";
        circle.style.color      = "orange";
        circle.style.filter     = "drop-shadow(0 0 8px #ff8e7d)";
    } else {
        status.innerText        = "SAFE";
        circle.style.color      = "#4ade80";
        circle.style.filter     = "drop-shadow(0 0 8px #4ade80)";
    }
}

function feature_bar(value, bar) {
    if (bar) bar.style.width = value + "%";
}

// ── Live Intel Feed (WebSocket) ───────────────────────────────────────────
// Targets the feed container by id="liveFeed" (added to index.html)
const feedList = document.getElementById('liveFeed');

const ws = new WebSocket("ws://127.0.0.1:8000/ws/feed");

ws.onmessage = function (event) {
    if (!feedList) return;
    const data    = JSON.parse(event.data);
    const itemDiv = document.createElement("div");
    itemDiv.className = "p-4 border-b border-white/5 hover:bg-surface-bright transition-colors cursor-pointer";

    let colorClass = "text-secondary-dim";
    if (data.status === "MALICIOUS") colorClass = "text-primary-dim";
    if (data.status === "SUSPICIOUS") colorClass = "text-primary";

    itemDiv.innerHTML = `
        <div class="flex justify-between mb-1">
            <span class="text-[10px] font-headline font-bold ${colorClass}">${data.status}</span>
            <span class="text-[9px] font-headline text-on-surface-variant">${data.time}</span>
        </div>
        <div class="text-[11px] font-headline text-on-surface truncate tracking-wider">${data.url}</div>
    `;

    feedList.insertBefore(itemDiv, feedList.firstChild);
    if (feedList.children.length > 50) feedList.removeChild(feedList.lastChild);
};

ws.onerror = function (e) {
    console.error("WebSocket error:", e);
};