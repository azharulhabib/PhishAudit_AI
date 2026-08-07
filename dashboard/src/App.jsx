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
            <Header />
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
                            ? <div className="loading">Loading...</div>
                            : <MetricsChart metrics={metrics} />
                        }
                    </div>

                    <div className="panel">
                        <div className="panel-title">
                            Detection Summary
                        </div>
                        <div style={{
                            display: "flex",
                            flexDirection: "column",
                            gap: "12px",
                            marginTop: "8px"
                        }}>
                            {[
                                {
                                    label: "Phishing Rate",
                                    value: stats?.total
                                        ? Math.round(
                                            (stats.phishing / stats.total) * 100
                                          )
                                        : 0,
                                    color: "var(--accent-red)"
                                },
                                {
                                    label: "Safe Rate",
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
                                        color: "var(--text-secondary)"
                                    }}>
                                        <span>{item.label}</span>
                                        <span>{item.value}%</span>
                                    </div>
                                    <div style={{
                                        height: "6px",
                                        background: "var(--border)",
                                        borderRadius: "3px",
                                        overflow: "hidden"
                                    }}>
                                        <div style={{
                                            width: `${item.value}%`,
                                            height: "100%",
                                            background: item.color,
                                            borderRadius: "3px",
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
                        Recent Audit Logs
                    </div>
                    {loading
                        ? <div className="loading">Loading...</div>
                        : <AuditTable logs={logs.slice(0, 50)} />
                    }
                </div>

            </main>
        </div>
    );
}