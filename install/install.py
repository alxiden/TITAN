"""TITAN installer: initializes local SQLite database for CTI storage."""

import sys
from pathlib import Path

def main():
	# Lazy import to avoid hard dependency during packaging
	try:
		from backend.db_init import init_db, DEFAULT_DB_PATH
	except Exception as e:
		print(f"Failed to import DB initializer: {e}")
		sys.exit(1)

	# Allow custom path via CLI arg
	db_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_DB_PATH

	try:
		init_db(db_path)
	except Exception as e:
		print(f"Database initialization failed: {e}")
		sys.exit(2)

	print(f"TITAN database initialized at: {db_path}")


if __name__ == "__main__":
	main()
