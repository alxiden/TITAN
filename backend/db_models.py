from datetime import datetime
from typing import Optional

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Table, Boolean, Enum
from sqlalchemy.orm import declarative_base, relationship
import enum

Base = declarative_base()


class EventStatus(enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"


class EventType(enum.Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    BREACH = "breach"
    INSIDER_THREAT = "insider_threat"
    VULNERABILITY = "vulnerability"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class Event(Base):
    """Security incident/event - main entity"""
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=True)  # critical, high, medium, low
    type = Column(Enum(EventType), nullable=True)
    status = Column(Enum(EventStatus), default=EventStatus.OPEN, nullable=False)
    event_date = Column(DateTime, nullable=True)
    closed_date = Column(DateTime, nullable=True)
    detected_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    malware_instances = relationship("Malware", back_populates="event")
    phishing_instances = relationship("Phish", back_populates="event")
    mitigations = relationship("Mitigation", back_populates="event", cascade="all, delete-orphan")


class Malware(Base):
    """Malware instance linked to an event"""
    __tablename__ = "malware"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    family = Column(String(128), nullable=True)
    description = Column(Text, nullable=True)
    occurrence_date = Column(DateTime, nullable=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    event = relationship("Event", back_populates="malware_instances")
    iocs = relationship("IOC", back_populates="malware", cascade="all, delete-orphan")


class Phish(Base):
    """Phishing instance linked to an event"""
    __tablename__ = "phishing"
    id = Column(Integer, primary_key=True)
    subject = Column(String(256), nullable=True)
    sender = Column(String(256), nullable=True)
    target = Column(String(256), nullable=True)
    description = Column(Text, nullable=True)
    occurrence_date = Column(DateTime, nullable=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    event = relationship("Event", back_populates="phishing_instances")
    iocs = relationship("IOC", back_populates="phish", cascade="all, delete-orphan")


class IOC(Base):
    """Indicator of Compromise - linked to malware or phishing"""
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True)
    type = Column(String(64), nullable=False)  # IP, domain, hash, url, email, file_path
    value = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    confidence = Column(Integer, nullable=True)  # 0-100
    
    # Link to either malware or phishing
    malware_id = Column(Integer, ForeignKey("malware.id"), nullable=True)
    phish_id = Column(Integer, ForeignKey("phishing.id"), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    malware = relationship("Malware", back_populates="iocs")
    phish = relationship("Phish", back_populates="iocs")


class Mitigation(Base):
    """Mitigation action for an event"""
    __tablename__ = "mitigations"
    id = Column(Integer, primary_key=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    assigned_to = Column(String(128), nullable=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    event = relationship("Event", back_populates="mitigations")
