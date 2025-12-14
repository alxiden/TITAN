import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .db_models import Base
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


def get_session(path: Path = DEFAULT_DB_PATH):
    engine = init_db(path)
    return sessionmaker(bind=engine, future=True)()
