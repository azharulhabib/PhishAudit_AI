from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime
from connection import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    result = Column(String, nullable=False)
    score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Whitelist(Base):
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String, unique=True, nullable=False)