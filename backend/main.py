from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from connection import SessionLocal, engine, get_db
from database.models import AuditLog, Base
from ml_engine import predict
from database.models import AuditLog, Base, ModelMetrics


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
    result = predict(request.url)


    audit_log = AuditLog(
        url=request.url,
        result=result["status"],
        score=result["score"],
        features_used=result["features"]
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    return {
        "url": request.url,
        "status": result["status"],
        "score": result["score"],
        "db_id": audit_log.id,
        "recommendation": (
            "block" if result["status"] == "Phishing"
            else "allow"
        ),
        "error": result.get("error")
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
            "accuracy":      0.9305,
            "precision":     0.7874,
            "recall":        0.8408,
            "f1_score":      0.8133,
            "roc_auc":       0.9614,
            "model_version": "rf_v1.0",
            "source":        "default"
        }

    return {
        "accuracy":      0.9305,
        "precision":     latest.precision,
        "recall":        latest.recall,
        "f1_score":      latest.f1_score,
        "roc_auc":       latest.roc_auc,
        "model_version": latest.model_version,
        "source":        "database"
    }