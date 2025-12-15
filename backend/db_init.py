import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .db_models import Base
DEFAULT_MALWARE_FAMILIES = [
    "Emotet",
    "TrickBot",
    "QakBot",
    "Dridex",
    "LockBit",
    "Conti",
    "Ryuk",
    "WannaCry",
    "NotPetya",
    "Zeus",
    "AgentTesla",
    "FormBook",
    "RedLine Stealer",
    "Remcos",
    "Cobalt Strike",
    "IcedID",
    "Azorult",
    "AsyncRAT",
    "Lokibot",
    "Raccoon Stealer",
]
from sqlalchemy import text

DEFAULT_DB_PATH = Path(os.environ.get("TITAN_DB_PATH", "./TITAN-data/titan.sqlite")).resolve()


def get_database_url(path: Path = DEFAULT_DB_PATH) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path}"


def init_db(path: Path = DEFAULT_DB_PATH):
    url = get_database_url(path)
    engine = create_engine(url, future=True)
    Base.metadata.create_all(engine)
    ensure_schema(engine)
    return engine


def ensure_schema(engine):
    """Lightweight schema migrations for SQLite: add missing columns."""
    with engine.connect() as conn:
        # Check events table columns
        cols = conn.execute(text("PRAGMA table_info(events)")).fetchall()
        col_names = {c[1] for c in cols}  # (cid, name, type, ...)
        if "closed_date" not in col_names:
            conn.execute(text("ALTER TABLE events ADD COLUMN closed_date DATETIME"))
            conn.commit()

        # Check malware table columns
        m_cols = conn.execute(text("PRAGMA table_info(malware)")).fetchall()
        m_col_names = {c[1] for c in m_cols}
        if "family_id" not in m_col_names:
            conn.execute(text("ALTER TABLE malware ADD COLUMN family_id INTEGER"))
            conn.commit()

        # Seed default malware families if table exists and is empty
        fam_cols = conn.execute(text("PRAGMA table_info(malware_families)")).fetchall()
        if fam_cols:
            existing = conn.execute(text("SELECT name FROM malware_families")).fetchall()
            existing_lower = {row[0].strip().lower() for row in existing if row[0]}
            to_insert = [name for name in DEFAULT_MALWARE_FAMILIES if name.strip().lower() not in existing_lower]
            if to_insert:
                conn.execute(
                    text("INSERT OR IGNORE INTO malware_families (name, created_at) VALUES (:name, CURRENT_TIMESTAMP)"),
                    [{"name": n} for n in to_insert],
                )
                conn.commit()


def get_session(path: Path = DEFAULT_DB_PATH):
    engine = init_db(path)
    return sessionmaker(bind=engine, future=True)()
