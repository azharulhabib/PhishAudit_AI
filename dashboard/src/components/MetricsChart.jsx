import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer, Cell
} from "recharts";

export default function MetricsChart({ metrics, theme = "light" }) {
    if (!metrics || !metrics.available) {
        return (
            <div className="empty-state">
                No metrics recorded yet. Run train_model.py
                and seed the model_metrics table.
            </div>
        );
    }

    const data = [
        { name: "Accuracy",  value: Math.round((metrics.accuracy  ?? 0) * 100) },
        { name: "Precision", value: Math.round((metrics.precision ?? 0) * 100) },
        { name: "Recall",    value: Math.round((metrics.recall    ?? 0) * 100) },
        { name: "F1 Score",  value: Math.round((metrics.f1_score  ?? 0) * 100) },
        { name: "ROC-AUC",   value: Math.round((metrics.roc_auc   ?? 0) * 100) },
    ];

    const colors = ["#2563eb", "#16a34a", "#d97706", "#7c3aed", "#dc2626"];

    const isLight = theme === "light";
    const gridColor = isLight ? "#e2e8f0" : "#2d3748";
    const tickColor = isLight ? "#64748b" : "#a0aec0";
    const tooltipBg = isLight ? "#ffffff" : "#1e2533";
    const tooltipBorder = isLight ? "#e2e8f0" : "#2d3748";
    const tooltipText = isLight ? "#0f172a" : "#f7fafc";

    return (
        <ResponsiveContainer width="100%" height={220}>
            <BarChart
                data={data}
                margin={{ top: 10, right: 10, left: -20, bottom: 5 }}
            >
                <CartesianGrid
                    strokeDasharray="3 3"
                    stroke={gridColor}
                    vertical={false}
                />
                <XAxis
                    dataKey="name"
                    tick={{ fill: tickColor, fontSize: 11, fontWeight: 500 }}
                    axisLine={false}
                    tickLine={false}
                />
                <YAxis
                    domain={[0, 100]}
                    tick={{ fill: tickColor, fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(v) => `${v}%`}
                />
                <Tooltip
                    contentStyle={{
                        background: tooltipBg,
                        border: `1px solid ${tooltipBorder}`,
                        borderRadius: "8px",
                        fontSize: "12px",
                        color: tooltipText,
                        boxShadow: isLight
                            ? "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.05)"
                            : "0 4px 6px -1px rgba(0, 0, 0, 0.3)"
                    }}
                    formatter={(value) => [`${value}%`, ""]}
                    cursor={{ fill: isLight ? "rgba(0, 0, 0, 0.03)" : "rgba(255, 255, 255, 0.03)" }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                    {data.map((_, index) => (
                        <Cell key={index} fill={colors[index]} />
                    ))}
                </Bar>
            </BarChart>
        </ResponsiveContainer>
    );
}