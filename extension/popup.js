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
});