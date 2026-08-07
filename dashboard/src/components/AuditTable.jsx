export default function AuditTable({ logs }) {
    if (!logs || logs.length === 0) {
        return <div className="empty-state">No audit logs found.</div>;
    }

    function getScoreClass(score) {
        if (score >= 0.7) return "danger";
        if (score >= 0.4) return "warning";
        return "safe";
    }

    function formatTime(timestamp) {
        if (!timestamp) return "—";
        return new Date(timestamp).toLocaleTimeString();
    }

    return (
        <table className="audit-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Risk Score</th>
                    <th>Time</th>
                </tr>
            </thead>
            <tbody>
                {logs.map((log) => {
                    const score = log.score ?? 0;
                    const pct = Math.round(score * 100);
                    const cls = getScoreClass(score);
                    const status = (log.result || "unknown").toLowerCase();

                    return (
                        <tr key={log.id}>
                            <td style={{ color: "var(--text-muted)" }}>
                                #{log.id}
                            </td>
                            <td className="url-cell" title={log.url}>
                                {log.url}
                            </td>
                            <td>
                                <span className={`badge ${status}`}>
                                    {log.result}
                                </span>
                            </td>
                            <td>
                                <div className="score-cell">
                                    <div className="score-bar-mini">
                                        <div
                                            className={`score-fill ${cls}`}
                                            style={{ width: `${pct}%` }}
                                        />
                                    </div>
                                    <span style={{
                                        fontSize: "11px",
                                        color: "var(--text-muted)"
                                    }}>
                                        {pct}%
                                    </span>
                                </div>
                            </td>
                            <td style={{ color: "var(--text-muted)" }}>
                                {formatTime(log.timestamp)}
                            </td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}