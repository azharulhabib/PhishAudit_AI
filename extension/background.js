chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
        const targetUrl = details.url;
        console.log("Intercepted URL:", targetUrl);

        fetch("http://localhost:8000/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetUrl })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Server Response:", data);
        })
        .catch(error => console.error("Connection Error:", error));
    }
});