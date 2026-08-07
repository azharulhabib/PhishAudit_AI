export default function StatsCard({ label, value, sub, color }) {
    return (
        <div className={`stats-card ${color}`}>
            <div className="card-label">{label}</div>
            <div className="card-value">{value}</div>
            {sub && <div className="card-sub">{sub}</div>}
        </div>
    );
}