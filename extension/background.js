chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
        const targetUrl = details.url;
        if (
            targetUrl.startsWith("chrome://") ||
            targetUrl.startsWith("chrome-extension://") ||
            targetUrl.startsWith("about:")
        ) {
            return;
        }

        console.log("[PhishAudit] Intercepted URL:", targetUrl);

        fetch("http://localhost:8000/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetUrl })
        })
        .then(response => response.json())
        .then(data => {
            console.log("[PhishAudit] Server Response:", data);

            if (data.status === "Phishing") {
                //notify user
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icons/icon48.png",
                    title: "⚠️ PhishAudit Warning",
                    message: `Suspicious URL detected!\n${targetUrl}\nRisk Score: ${(data.score * 100).toFixed(0)}%`
                });
                console.warn("[PhishAudit] PHISHING DETECTED:", targetUrl);
            } else {
                console.log("[PhishAudit] Safe:", targetUrl);
            }
        })
        .catch(error => {
            console.warn("[PhishAudit] Backend unavailable:", error.message);
        });
    }
});