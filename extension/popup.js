document.addEventListener("DOMContentLoaded", () => {

    const statusCard      = document.getElementById("statusCard");
    const statusIndicator = document.getElementById("statusIndicator");
    const statusLabel     = document.getElementById("statusLabel");
    const statusScore     = document.getElementById("statusScore");
    const urlText         = document.getElementById("urlText");
    const scoreSection    = document.getElementById("scoreSection");
    const scoreBar        = document.getElementById("scoreBar");
    const scoreValue      = document.getElementById("scoreValue");
    const timestamp       = document.getElementById("timestamp");
    const btnTrust        = document.getElementById("btnTrust");
    const btnReport       = document.getElementById("btnReport");
    const themeToggle     = document.getElementById("themeToggle");

    const sunSvg = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="5"></circle>
            <line x1="12" y1="1" x2="12" y2="3"></line>
            <line x1="12" y1="21" x2="12" y2="23"></line>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
            <line x1="1" y1="12" x2="3" y2="12"></line>
            <line x1="21" y1="12" x2="23" y2="12"></line>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        </svg>
    `;

    const moonSvg = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
        </svg>
    `;

    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        if (themeToggle) {
            themeToggle.innerHTML = theme === "dark" ? sunSvg : moonSvg;
            themeToggle.title = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
        }
    }

    // Load initial theme preference
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get("theme", (res) => {
            const currentTheme = res.theme || "light";
            applyTheme(currentTheme);
        });
    } else {
        const currentTheme = localStorage.getItem("phishAudit_theme") || "light";
        applyTheme(currentTheme);
    }

    // Toggle theme handler
    if (themeToggle) {
        themeToggle.addEventListener("click", () => {
            const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
            const newTheme = currentTheme === "light" ? "dark" : "light";
            applyTheme(newTheme);

            if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
                chrome.storage.local.set({ theme: newTheme });
            } else {
                localStorage.setItem("phishAudit_theme", newTheme);
            }
        });
    }

    // Audit result loading
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get("lastAudit", (result) => {
            const audit = result.lastAudit;

            if (!audit) {
                statusLabel.textContent = "No audit data yet.";
                statusScore.textContent = "Visit a website to begin.";
                return;
            }

            urlText.textContent = audit.url || "—";

            if (audit.timestamp) {
                const date = new Date(audit.timestamp);
                timestamp.textContent = `Last audited: ${date.toLocaleTimeString()}`;
            }

            if (audit.status === "Safe") {
                statusCard.classList.add("safe");
                statusLabel.textContent = "Safe";
                statusScore.textContent = "No threats detected.";
            } else if (audit.status === "Phishing") {
                statusCard.classList.add("phishing");
                statusLabel.textContent = "Phishing Detected";
                statusScore.textContent = "Do not enter credentials on this site.";
            } else {
                statusCard.classList.add("unknown");
                statusLabel.textContent = "Unknown";
                statusScore.textContent = "Backend unavailable.";
            }

            if (audit.score !== null && audit.score !== undefined) {
                scoreSection.style.display = "flex";
                const pct = Math.round(audit.score * 100);
                scoreBar.style.width = `${pct}%`;
                scoreValue.textContent = `${pct}%`;

                if (pct >= 70) {
                    scoreBar.classList.add("danger");
                } else if (pct >= 40) {
                    scoreBar.classList.add("warning");
                }
            }
        });

        btnTrust.addEventListener("click", () => {
            chrome.storage.local.get("lastAudit", (result) => {
                if (!result.lastAudit) return;

                try {
                    const url = new URL(result.lastAudit.url);
                    const domain = url.hostname;

                    chrome.storage.local.get("trustedDomains", (data) => {
                        const trusted = data.trustedDomains || [];
                        if (!trusted.includes(domain)) {
                            trusted.push(domain);
                            chrome.storage.local.set(
                                { trustedDomains: trusted },
                                () => {
                                    btnTrust.textContent = "Trusted";
                                    btnTrust.disabled = true;
                                }
                            );
                        }
                    });
                } catch (e) {
                    console.error("Invalid URL:", e);
                }
            });
        });

        btnReport.addEventListener("click", () => {
            chrome.storage.local.get("lastAudit", (result) => {
                if (!result.lastAudit) return;

                chrome.storage.local.get("falsePositives", (data) => {
                    const reports = data.falsePositives || [];
                    reports.push({
                        url: result.lastAudit.url,
                        reportedAt: new Date().toISOString()
                    });
                    chrome.storage.local.set(
                        { falsePositives: reports },
                        () => {
                            btnReport.textContent = "Reported";
                            btnReport.disabled = true;
                        }
                    );
                });
            });
        });
    }
});