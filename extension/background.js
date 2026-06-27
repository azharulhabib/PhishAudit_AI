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
        .then(response => response.json())
        .then(data => {
            console.log("[PhishAudit] Audit result:", data);

            if (data.status === "Phishing") {
                //notify user
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
        });
    }
});