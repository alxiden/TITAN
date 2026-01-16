from datetime import datetime
from typing import Optional

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Table, Boolean, Enum, Float
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

apt_vulnerabilities = Table(
    'apt_vulnerabilities',
    Base.metadata,
    Column('apt_id', Integer, ForeignKey('apts.id'), primary_key=True),
    Column('vulnerability_id', Integer, ForeignKey('vulnerabilities.id'), primary_key=True)
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


class ClusterType(enum.Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    MIXED = "mixed"


# Association tables for research clusters
cluster_phishing = Table(
    'cluster_phishing',
    Base.metadata,
    Column('cluster_id', Integer, ForeignKey('clusters.id'), primary_key=True),
    Column('phish_id', Integer, ForeignKey('phishing.id'), primary_key=True)
)

cluster_malware = Table(
    'cluster_malware',
    Base.metadata,
    Column('cluster_id', Integer, ForeignKey('clusters.id'), primary_key=True),
    Column('malware_id', Integer, ForeignKey('malware.id'), primary_key=True)
)

cluster_iocs = Table(
    'cluster_iocs',
    Base.metadata,
    Column('cluster_id', Integer, ForeignKey('clusters.id'), primary_key=True),
    Column('ioc_id', Integer, ForeignKey('iocs.id'), primary_key=True)
)

cluster_apts = Table(
    'cluster_apts',
    Base.metadata,
    Column('cluster_id', Integer, ForeignKey('clusters.id'), primary_key=True),
    Column('apt_id', Integer, ForeignKey('apts.id'), primary_key=True)
)

# Optional event membership for clusters
cluster_events = Table(
    'cluster_events',
    Base.metadata,
    Column('cluster_id', Integer, ForeignKey('clusters.id'), primary_key=True),
    Column('event_id', Integer, ForeignKey('events.id'), primary_key=True)
)


class Cluster(Base):
    """Research cluster linking phishing, malware, IOCs, and inferred APT overlap."""
    __tablename__ = "clusters"
    id = Column(Integer, primary_key=True)
    title = Column(String(256), nullable=False)
    summary = Column(Text, nullable=True)
    cluster_type = Column(Enum(ClusterType), nullable=False)
    time_start = Column(DateTime, nullable=True)
    time_end = Column(DateTime, nullable=True)
    score = Column(Float, nullable=True)  # general confidence/strength 0-100
    apt_overlap_score = Column(Float, nullable=True)  # degree of linkage to mapped APTs
    shared_ioc_count = Column(Integer, default=0, nullable=False)
    shared_infra_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    phishing = relationship("Phish", secondary=cluster_phishing, back_populates="clusters")
    malware = relationship("Malware", secondary=cluster_malware, back_populates="clusters")
    iocs = relationship("IOC", secondary=cluster_iocs, back_populates="clusters")
    apts = relationship("APT", secondary=cluster_apts, back_populates="clusters")
    events = relationship("Event", secondary=cluster_events, back_populates="clusters")


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
    vulnerabilities = relationship("Vulnerability", secondary=apt_vulnerabilities, back_populates="apts")
    clusters = relationship("Cluster", secondary=cluster_apts, back_populates="apts")


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
    vulnerability_instances = relationship("Vulnerability", back_populates="event")
    mitigations = relationship("Mitigation", back_populates="event", cascade="all, delete-orphan")
    clusters = relationship("Cluster", secondary=cluster_events, back_populates="events")


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
    clusters = relationship("Cluster", secondary=cluster_malware, back_populates="malware")


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
    clusters = relationship("Cluster", secondary=cluster_phishing, back_populates="phishing")


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
    clusters = relationship("Cluster", secondary=cluster_iocs, back_populates="iocs")


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


class Vulnerability(Base):
    """Vulnerability instance - CVE or other security vulnerabilities"""
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(32), nullable=True)  # CVE-YYYY-NNNNN format
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=True)  # critical, high, medium, low
    cvss_score = Column(String(16), nullable=True)  # e.g., "9.8", "7.5"
    affected_product = Column(String(256), nullable=True)
    affected_version = Column(String(128), nullable=True)
    patch_available = Column(Boolean, default=False, nullable=False)
    patch_details = Column(Text, nullable=True)
    discovered_date = Column(DateTime, nullable=True)  # When vulnerability was first discovered
    patched_date = Column(DateTime, nullable=True)  # When patch was applied
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    apts = relationship("APT", secondary=apt_vulnerabilities, back_populates="vulnerabilities")
    event = relationship("Event", back_populates="vulnerability_instances")
