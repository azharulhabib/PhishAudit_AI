export default function Header({ theme = "light", onToggleTheme }) {
    return (
        <header style={{
            background: "var(--bg-secondary)",
            borderBottom: "1px solid var(--border)",
            padding: "0 32px",
            height: "58px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            position: "sticky",
            top: 0,
            zIndex: 100
        }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <img
                    src="/icon48.png"
                    alt="PhishAudit AI"
                    style={{ width: "28px", height: "28px", borderRadius: "6px" }}
                />
                <div>
                    <div style={{
                        fontSize: "14px",
                        fontWeight: "600",
                        color: "var(--text-primary)",
                        letterSpacing: "0.2px"
                    }}>
                        PhishAudit AI
                    </div>
                    <div style={{
                        fontSize: "10px",
                        color: "var(--text-muted)",
                        fontWeight: "500"
                    }}>
                        Administrative Dashboard
                    </div>
                </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                <div style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    fontSize: "11px",
                    fontWeight: "500",
                    color: "var(--text-secondary)",
                    padding: "4px 10px",
                    borderRadius: "20px",
                    background: "var(--bg-primary)",
                    border: "1px solid var(--border)"
                }}>
                    <div style={{
                        width: "7px",
                        height: "7px",
                        borderRadius: "50%",
                        background: "var(--accent-green)",
                        boxShadow: "0 0 6px var(--accent-green)"
                    }} />
                    Backend Online
                </div>

                <button
                    className="theme-toggle-btn"
                    onClick={onToggleTheme}
                    title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                    aria-label="Toggle color theme"
                >
                    {theme === "dark" ? (
                        /* Sun Icon */
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
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
                    ) : (
                        /* Moon Icon */
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                        </svg>
                    )}
                </button>
            </div>
        </header>
    );
}