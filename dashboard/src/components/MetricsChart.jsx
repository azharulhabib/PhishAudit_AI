import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer, Cell
} from "recharts";

export default function MetricsChart({ metrics }) {
    if (!metrics) {
        return <div className="empty-state">No metrics available.</div>;
    }

    const data = [
        { name: "Accuracy",  value: Math.round((metrics.accuracy  ?? 0) * 100) },
        { name: "Precision", value: Math.round((metrics.precision ?? 0) * 100) },
        { name: "Recall",    value: Math.round((metrics.recall    ?? 0) * 100) },
        { name: "F1 Score",  value: Math.round((metrics.f1_score  ?? 0) * 100) },
        { name: "ROC-AUC",   value: Math.round((metrics.roc_auc   ?? 0) * 100) },
    ];

    const colors = ["#3182ce", "#38a169", "#d69e2e", "#805ad5", "#e53e3e"];

    return (
        <ResponsiveContainer width="100%" height={220}>
            <BarChart
                data={data}
                margin={{ top: 5, right: 10, left: -20, bottom: 5 }}
            >
                <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#2d3748"
                    vertical={false}
                />
                <XAxis
                    dataKey="name"
                    tick={{ fill: "#4a5568", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                />
                <YAxis
                    domain={[0, 100]}
                    tick={{ fill: "#4a5568", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(v) => `${v}%`}
                />
                <Tooltip
                    contentStyle={{
                        background: "#1e2533",
                        border: "1px solid #2d3748",
                        borderRadius: "8px",
                        fontSize: "12px"
                    }}
                    formatter={(value) => [`${value}%`, ""]}
                    cursor={{ fill: "rgba(255,255,255,0.03)" }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {data.map((_, index) => (
                        <Cell key={index} fill={colors[index]} />
                    ))}
                </Bar>
            </BarChart>
        </ResponsiveContainer>
    );
}