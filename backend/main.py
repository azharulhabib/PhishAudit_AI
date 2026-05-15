from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from connection import SessionLocal, engine, get_db
from database.models import AuditLog, Base

Base.metadata.create_all(bind=engine)

app = FastAPI(title="PhishAudit AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLAuditRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"status": "Online", "message": "PhishAudit AI Backend is Running"}

@app.post("/audit")
async def audit_url(request: URLAuditRequest, db: Session = Depends(get_db)):
    # This will be replaced with real ML in Sprint 2
    suspicious_keywords = ["phish", "login", "verify", "secure", "account", "update", "confirm", "bank"]
    is_suspicious = any(kw in request.url.lower() for kw in suspicious_keywords)
    status = "Phishing" if is_suspicious else "Safe"
    score = 0.95 if is_suspicious else 0.05
    
    #  Save to database
    audit_log = AuditLog(
        url=request.url,
        result=status,
        score=score,
        features_used=None
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    return {
        "url": request.url,
        "status": status,
        "score": audit_log.score,
        "db_id": audit_log.id,
        "recommendation": "Block" if is_suspicious else "Allow"
    }