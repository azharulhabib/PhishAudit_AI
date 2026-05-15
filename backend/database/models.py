from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from connection import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    audit_logs = relationship("AuditLog", back_populates="user")
    whitelist_entries = relationship("Whitelist", back_populates="added_by_user")
    model_metrics = relationship("ModelMetrics", back_populates="recorded_by_user")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    result = Column(String, nullable=False)
    score = Column(Float)
    features_used = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationship
    user = relationship("User", back_populates="audit_logs")


class Whitelist(Base):
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String, unique=True, nullable=False)
    added_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship
    added_by_user = relationship("User", back_populates="whitelist_entries")


class ModelMetrics(Base):
    __tablename__ = "model_metrics"

    id = Column(Integer, primary_key=True, index=True)
    model_version = Column(String(100), nullable=False)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    roc_auc = Column(Float, nullable=True)
    urls_audited = Column(Integer, nullable=True)
    evaluated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    recorded_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationship
    recorded_by_user = relationship("User", back_populates="model_metrics")