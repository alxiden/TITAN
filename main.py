from pathlib import Path
import os

from backend.db_init import init_db, DEFAULT_DB_PATH

# Prefer env override for DB path
DB_PATH = Path(os.environ.get("TITAN_DB_PATH", DEFAULT_DB_PATH)).resolve()

# Initialize DB on start
init_db(DB_PATH)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.api:app", host="0.0.0.0", port=8000, reload=True)
