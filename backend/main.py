from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
async def audit_url(request: URLAuditRequest):
    is_suspicious = "phish" in request.url.lower() or "test" in request.url.lower()
    
    return {
        "url": request.url,
        "status": "Phishing" if is_suspicious else "Safe",
        "score": 0.98 if is_suspicious else 0.01,
        "recommendation": "Block" if is_suspicious else "Allow"
    }