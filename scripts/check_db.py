import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pipeline.store as store
from pipeline.store import connect

print("store module file :", store.__file__)
print("LAB_DB            :", repr(os.environ.get("LAB_DB")))
print("DEFAULT_DB        :", repr(store.DEFAULT_DB))

conn = connect()
print("connect() returned:", type(conn).__name__)

tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("tables            :", tables)

for table in tables:
    count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    print(f"  {table}: {count} rows")

conn.close()
print("OK")