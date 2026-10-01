import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";
import Header from "./components/Header";
import StatsCard from "./components/StatsCard";
import AuditTable from "./components/AuditTable";
import MetricsChart from "./components/MetricsChart";

const API = "http://localhost:8000";

export default function App() {
    const [logs, setLogs]       = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [stats, setStats]     = useState(null);
    const [loading, setLoading] = useState(true);
    const [theme, setTheme]     = useState(() => {
        try {
            return localStorage.getItem("phishAudit_theme") || "light";
        } catch (e) {
            return "light";
        }
    });

    const toggleTheme = () => {
        const nextTheme = theme === "light" ? "dark" : "light";
        // Apply synchronously to DOM immediately to prevent any render desync or flash
        document.documentElement.setAttribute("data-theme", nextTheme);
        try {
            localStorage.setItem("phishAudit_theme", nextTheme);
        } catch (e) {}
        setTheme(nextTheme);
    };

    useEffect(() => {
        document.documentElement.setAttribute("data-theme", theme);
    }, [theme]);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, []);

    async function fetchData() {
        try {
            const [logsRes, metricsRes] = await Promise.all([
                axios.get(`${API}/logs`),
                axios.get(`${API}/metrics`)
            ]);

            const logsData = logsRes.data.logs || [];
            setLogs(logsData);
            setMetrics(metricsRes.data);

            const total    = logsData.length;
            const phishing = logsData.filter(
                l => l.result === "Phishing"
            ).length;
            const safe     = total - phishing;
            const avgScore = total > 0
                ? (logsData.reduce((s, l) => s + (l.score || 0), 0) / total)
                : 0;

            setStats({ total, phishing, safe, avgScore });
        } catch (err) {
            console.error("Failed to fetch dashboard data:", err);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="dashboard">
            <Header theme={theme} onToggleTheme={toggleTheme} />
            <main className="main-content">

                {/* Stats Row */}
                <div className="stats-grid">
                    <StatsCard
                        label="Total Audits"
                        value={stats?.total ?? "—"}
                        sub="All URLs audited"
                        color="blue"
                    />
                    <StatsCard
                        label="Phishing Detected"
                        value={stats?.phishing ?? "—"}
                        sub="Flagged as malicious"
                        color="red"
                    />
                    <StatsCard
                        label="Safe URLs"
                        value={stats?.safe ?? "—"}
                        sub="Passed audit"
                        color="green"
                    />
                    <StatsCard
                        label="Avg Risk Score"
                        value={
                            stats?.avgScore != null
                                ? `${Math.round(stats.avgScore * 100)}%`
                                : "—"
                        }
                        sub="Across all audits"
                        color="yellow"
                    />
                </div>

                <div className="charts-row">
                    <div className="panel">
                        <div className="panel-title">
                            Model Performance Metrics
                        </div>
                        {loading
                            ? <div className="loading">Loading metrics...</div>
                            : <MetricsChart metrics={metrics} theme={theme} />
                        }
                    </div>

                    <div className="panel">
                        <div className="panel-title">
                            Detection Summary
                        </div>
                        <div style={{
                            display: "flex",
                            flexDirection: "column",
                            gap: "16px",
                            marginTop: "12px"
                        }}>
                            {[
                                {
                                    label: "Phishing Detection Rate",
                                    value: stats?.total
                                        ? Math.round(
                                            (stats.phishing / stats.total) * 100
                                          )
                                        : 0,
                                    color: "var(--accent-red)"
                                },
                                {
                                    label: "Safe URLs Rate",
                                    value: stats?.total
                                        ? Math.round(
                                            (stats.safe / stats.total) * 100
                                          )
                                        : 0,
                                    color: "var(--accent-green)"
                                },
                            ].map((item) => (
                                <div key={item.label}>
                                    <div style={{
                                        display: "flex",
                                        justifyContent: "space-between",
                                        marginBottom: "6px",
                                        fontSize: "12px",
                                        fontWeight: "500",
                                        color: "var(--text-secondary)"
                                    }}>
                                        <span>{item.label}</span>
                                        <span style={{ fontWeight: "600", color: "var(--text-primary)" }}>{item.value}%</span>
                                    </div>
                                    <div style={{
                                        height: "7px",
                                        background: "var(--border)",
                                        borderRadius: "4px",
                                        overflow: "hidden"
                                    }}>
                                        <div style={{
                                            width: `${item.value}%`,
                                            height: "100%",
                                            background: item.color,
                                            borderRadius: "4px",
                                            transition: "width 0.5s ease"
                                        }} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="panel">
                    <div className="panel-title">
                        Recent URL Audit Logs
                    </div>
                    {loading
                        ? <div className="loading">Loading audit records...</div>
                        : (
                            <div className="audit-table-wrapper">
                                <AuditTable logs={logs.slice(0, 50)} />
                            </div>
                        )
                    }
                </div>

            </main>
        </div>
    );
}