from datetime import datetime
from typing import Optional

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Table, Boolean, Enum
from sqlalchemy.orm import declarative_base, relationship
import enum

Base = declarative_base()

# Association tables for many-to-many relationships with APT
apt_events = Table(
    'apt_events',
    Base.metadata,
    Column('apt_id', Integer, ForeignKey('apts.id'), primary_key=True),
    Column('event_id', Integer, ForeignKey('events.id'), primary_key=True)
)

apt_malware = Table(
    'apt_malware',
    Base.metadata,
    Column('apt_id', Integer, ForeignKey('apts.id'), primary_key=True),
    Column('malware_id', Integer, ForeignKey('malware.id'), primary_key=True)
)

apt_phishing = Table(
    'apt_phishing',
    Base.metadata,
    Column('apt_id', Integer, ForeignKey('apts.id'), primary_key=True),
    Column('phish_id', Integer, ForeignKey('phishing.id'), primary_key=True)
)

apt_iocs = Table(
    'apt_iocs',
    Base.metadata,
    Column('apt_id', Integer, ForeignKey('apts.id'), primary_key=True),
    Column('ioc_id', Integer, ForeignKey('iocs.id'), primary_key=True)
)


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


class APT(Base):
    """Advanced Persistent Threat entity"""
    __tablename__ = "apts"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False, unique=True)
    aliases = Column(Text, nullable=True)  # Comma-separated list of known aliases
    description = Column(Text, nullable=True)
    country_origin = Column(String(128), nullable=True)
    primary_targets = Column(Text, nullable=True)  # Comma-separated list
    tactics = Column(Text, nullable=True)  # Comma-separated MITRE ATT&CK tactics
    techniques = Column(Text, nullable=True)  # Comma-separated MITRE ATT&CK techniques
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    events = relationship("Event", secondary=apt_events, back_populates="apts")
    malware = relationship("Malware", secondary=apt_malware, back_populates="apts")
    phishing = relationship("Phish", secondary=apt_phishing, back_populates="apts")
    iocs = relationship("IOC", secondary=apt_iocs, back_populates="apts")


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
    apts = relationship("APT", secondary=apt_events, back_populates="events")
    malware_instances = relationship("Malware", back_populates="event")
    phishing_instances = relationship("Phish", back_populates="event")
    mitigations = relationship("Mitigation", back_populates="event", cascade="all, delete-orphan")


class Malware(Base):
    """Malware instance linked to an event"""
    __tablename__ = "malware"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    family = Column(String(128), nullable=True)
    family_id = Column(Integer, ForeignKey("malware_families.id"), nullable=True)
    category = Column(String(128), nullable=True)
    category_id = Column(Integer, ForeignKey("malware_categories.id"), nullable=True)
    description = Column(Text, nullable=True)
    occurrence_date = Column(DateTime, nullable=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    apts = relationship("APT", secondary=apt_malware, back_populates="malware")
    event = relationship("Event", back_populates="malware_instances")
    iocs = relationship("IOC", back_populates="malware", cascade="all, delete-orphan")
    family_ref = relationship("MalwareFamily", back_populates="malware_items")
    category_ref = relationship("MalwareCategory", back_populates="malware_items")


class Phish(Base):
    """Phishing instance linked to an event"""
    __tablename__ = "phishing"
    id = Column(Integer, primary_key=True)
    subject = Column(String(256), nullable=True)
    sender = Column(String(256), nullable=True)
    target = Column(String(256), nullable=True)
    description = Column(Text, nullable=True)
    risk_level = Column(String(16), nullable=True)  # low, medium, high, critical
    occurrence_date = Column(DateTime, nullable=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    apts = relationship("APT", secondary=apt_phishing, back_populates="phishing")
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
    apts = relationship("APT", secondary=apt_iocs, back_populates="iocs")
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


class MalwareFamily(Base):
    """Reference table for malware families"""
    __tablename__ = "malware_families"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    malware_items = relationship("Malware", back_populates="family_ref")


class MalwareCategory(Base):
    """Reference table for malware categories"""
    __tablename__ = "malware_categories"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    malware_items = relationship("Malware", back_populates="category_ref")
