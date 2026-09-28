from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .database import Base


class EmailRecord(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    sha256 = Column(String, index=True, nullable=False)
    sender = Column(String, index=True)
    reply_to = Column(String, nullable=True)
    return_path = Column(String, nullable=True)
    subject = Column(String)
    date_header = Column(String, nullable=True)
    raw_headers = Column(Text)  # full raw header block, for the analyst
    body_preview = Column(Text)

    fraud_score = Column(Float, default=0.0)
    verdict = Column(String, default="Clean")  # Clean / Suspicious / Fraudulent
    flagged = Column(Integer, default=0)  # 1 = shown on dashboard as flagged/spam

    origin_ip = Column(String, nullable=True)
    origin_country = Column(String, nullable=True)
    origin_city = Column(String, nullable=True)
    origin_lat = Column(Float, nullable=True)
    origin_lon = Column(Float, nullable=True)
    origin_isp = Column(String, nullable=True)
    origin_is_proxy = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)

    steps = relationship("AnalysisStep", back_populates="email", cascade="all, delete-orphan")


class AnalysisStep(Base):
    """
    One box in the analyst 'manual workflow' flowchart.
    status: green | red | amber
    details: JSON blob shown when the analyst clicks the box.
    """
    __tablename__ = "analysis_steps"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    order_index = Column(Integer, default=0)
    step_key = Column(String)
    title = Column(String)
    status = Column(String)  # green / red / amber
    summary = Column(String)
    details = Column(JSON)

    email = relationship("EmailRecord", back_populates="steps")
