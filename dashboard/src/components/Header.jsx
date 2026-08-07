export default function Header() {
    return (
        <header style={{
            background: "var(--bg-secondary)",
            borderBottom: "1px solid var(--border)",
            padding: "0 32px",
            height: "56px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            position: "sticky",
            top: 0,
            zIndex: 100
        }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <img
                    src="/icon48.png"
                    alt="PhishAudit AI"
                    style={{ width: "28px", height: "28px", borderRadius: "6px" }}
                />
                <div>
                    <div style={{
                        fontSize: "13px",
                        fontWeight: "600",
                        color: "var(--text-primary)"
                    }}>
                        PhishAudit AI
                    </div>
                    <div style={{
                        fontSize: "10px",
                        color: "var(--text-muted)"
                    }}>
                        Admin Dashboard
                    </div>
                </div>
            </div>

            <div style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                fontSize: "11px",
                color: "var(--text-muted)"
            }}>
                <div style={{
                    width: "6px",
                    height: "6px",
                    borderRadius: "50%",
                    background: "var(--accent-green)"
                }} />
                Backend Online
            </div>
        </header>
    );
}