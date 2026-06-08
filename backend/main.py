from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from connection import SessionLocal, engine, get_db
from database.models import AuditLog, Base
from ml_engine import predict


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