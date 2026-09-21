from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from urllib.parse import urlparse
from connection import SessionLocal, engine, get_db

from database.models import AuditLog, Base, ModelMetrics
from ml_engine import predict
from domain_gate import classify_domain
from hvt_domains import detect_combo_squatting, detect_high_risk_keywords


Base.metadata.create_all(bind=engine)

app = FastAPI(title="PhishAudit AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "chrome-extension://*"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLAuditRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {
        "status": "online",
        "service": "PhishAudit AI API"
    }

@app.post("/audit")
async def audit_url(
    request: URLAuditRequest,
    db: Session = Depends(get_db)
):
    url      = request.url
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""

    # ────────────────────────────────────────────────────
    # STAGE 1 — Domain Gate
    # Classifies domain into Tier 1, 2, or 3 based on
    # edit distance from trusted domain list.
    # ────────────────────────────────────────────────────
    gate = classify_domain(hostname)

    if gate["bypass"]:
        return {
            "url":            url,
            "status":         "Safe",
            "score":          0.0,
            "db_id":          None,
            "recommendation": "allow",
            "tier":           1,
            "threshold_used": 1.0,
            "source":         "trusted_domain",
            "combo_brand":    None,
            "keywords_found": [],
            "closest_match":  gate["closest_match"],
            "error":          None
        }

    # ────────────────────────────────────────────────────
    # STAGE 2 — HVT Combo-Squatting Check
    # Detects brand names embedded in wrong domains.
    # Overrides threshold to 0.25 if detected.
    # ────────────────────────────────────────────────────
    combo = detect_combo_squatting(hostname, url)

    if combo["detected"]:
        threshold = 0.25
        tier      = 4
        source    = "hvt_combo_squatting"
    else:
        threshold = gate["threshold"]
        tier      = gate["tier"]
        source    = "ml_model"

    # ────────────────────────────────────────────────────
    # STAGE 3 — High-Risk Keyword Context Shifting
    # Only applies to Tier 3 unknown domains.
    # Shifts threshold downward based on keyword count.
    # ────────────────────────────────────────────────────
    keyword_result = detect_high_risk_keywords(url)

    if tier == 3 and keyword_result["detected"]:
        if keyword_result["count"] >= 3:
            threshold = 0.35
        elif keyword_result["count"] >= 1:
            threshold = 0.50
        source = "keyword_context"

    # ────────────────────────────────────────────────────
    # STAGE 4 — ML Inference
    # Runs the Random Forest model with the threshold
    # determined by the preceding stages.
    # ────────────────────────────────────────────────────
    result = predict(url)
    status = "Phishing" if result["score"] >= threshold else "Safe"

    # ────────────────────────────────────────────────────
    # STAGE 5 — Persist to Database
    # ────────────────────────────────────────────────────
    audit_log = AuditLog(
        url=url,
        result=status,
        score=result["score"],
        features_used=result["features"]
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    return {
        "url":            url,
        "status":         status,
        "score":          result["score"],
        "db_id":          audit_log.id,
        "recommendation": "block" if status == "Phishing" else "allow",
        "tier":           tier,
        "threshold_used": threshold,
        "source":         source,
        "combo_brand":    combo.get("brand"),
        "keywords_found": keyword_result.get("keywords_found"),
        "closest_match":  gate.get("closest_match"),
        "error":          result.get("error")
    }

@app.get("/logs")
def get_logs(db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(
        AuditLog.timestamp.desc()
    ).limit(100).all()

    return {
        "logs": [
            {
                "id":        log.id,
                "url":       log.url,
                "result":    log.result,
                "score":     log.score,
                "timestamp": log.timestamp.isoformat()
                             if log.timestamp else None
            }
            for log in logs
        ]
    }


@app.get("/metrics")
def get_metrics(db: Session = Depends(get_db)):
    latest = db.query(ModelMetrics).order_by(
        ModelMetrics.evaluated_at.desc()
    ).first()

    if not latest:
        return {
            "available":     False,
            "message":       "No model metrics recorded yet. Run the evaluation script to populate metrics.",
            "model_version": None,
            "accuracy":      None,
            "precision":     None,
            "recall":        None,
            "f1_score":      None,
            "roc_auc":       None,
        }

    return {
        "available":     True,
        "model_version": latest.model_version,
        "accuracy":      latest.precision,
        "precision":     latest.precision,
        "recall":        latest.recall,
        "f1_score":      latest.f1_score,
        "roc_auc":       latest.roc_auc,
        "source":        "database"
    }