chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0) {
        const targetUrl = details.url;
        if (
            targetUrl.startsWith("chrome://") ||
            targetUrl.startsWith("chrome-extension://") ||
            targetUrl.startsWith("about:")
        ) {
            return;
        }

        console.log("[PhishAudit] Auditing URL:", targetUrl);

        fetch("http://localhost:8000/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetUrl })
        })
        .then(response => {
            if (!response.ok) {
                // Non-OK HTTP response: no verdict. Treat as Unknown.
                return {
                    url: targetUrl,
                    status: "Unknown",
                    score: null,
                    recommendation: "unavailable",
                    error: `Audit failed (HTTP ${response.status}).`
                };
            }
            return response.json();
        })
        .then(data => {
            console.log("[PhishAudit] Audit result:", data);

            // Fail closed: only an explicit Safe or Phishing verdict is
            // shown as such. Anything else (Unknown, missing, unexpected)
            // gets a grey "?" badge and never a safe/green state.
            if (data.status !== "Safe" && data.status !== "Phishing") {
                chrome.storage.local.set({
                    lastAudit: {
                        url: data.url || targetUrl,
                        status: "Unknown",
                        score: null,
                        recommendation: "unavailable",
                        error: data.error || "No verdict available.",
                        timestamp: new Date().toISOString()
                    }
                });
                chrome.action.setBadgeText({ text: "?", tabId: details.tabId });
                chrome.action.setBadgeBackgroundColor({
                    color: "#718096",
                    tabId: details.tabId
                });
                console.warn("[PhishAudit] No verdict (Unknown):", data.error);
                return;
            }

            chrome.storage.local.set({
                lastAudit: {
                    url: data.url,
                    status: data.status,
                    score: data.score,
                    recommendation: data.recommendation,
                    timestamp: new Date().toISOString()
                }
            });

            const badgeText = data.status === "Phishing" ? "!" : "";
            const badgeColor = data.status === "Phishing" ? "#e53e3e" : "#38a169";

            chrome.action.setBadgeText({
                text: badgeText,
                tabId: details.tabId
            });
            chrome.action.setBadgeBackgroundColor({
                color: badgeColor,
                tabId: details.tabId
            });
            if (data.status === "Phishing") {
                chrome.notifications.create({
                    type: "basic",
                    title: "PhishAudit Warning",
                    message: `Suspicious URL detected.\nRisk Score: ${(data.score * 100).toFixed(0)}%`
                });
                console.warn("[PhishAudit] Phishing detected:", targetUrl);
            } else {
                console.log("[PhishAudit] Safe:", targetUrl);
            }
        })
        .catch(() => {
            console.warn("[PhishAudit] Backend unavailable.");

            chrome.storage.local.set({
                lastAudit: {
                    url: targetUrl,
                    status: "Unknown",
                    score: null,
                    recommendation: "unavailable",
                    timestamp: new Date().toISOString()
                }
            });
        });
    }
});