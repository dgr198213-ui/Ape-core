import os
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
MIGRATIONS = sorted((ROOT / "migrations").glob("*.sql"))


@pytest.fixture
def pgdb():
    """Base de datos PostgreSQL nueva (con todas las migraciones) por prueba.
    Requiere APE_TEST_DSN con un superusuario."""
    dsn = os.environ.get("APE_TEST_DSN")
    if not dsn:
        pytest.skip("APE_TEST_DSN no definido")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.conninfo import make_conninfo

    admin = psycopg.connect(dsn, autocommit=True)
    name = "ape_t_" + uuid.uuid4().hex[:8]
    admin.execute(f"create database {name}")
    conninfo = make_conninfo(dsn, dbname=name)
    conn = psycopg.connect(conninfo, autocommit=True)
    for f in MIGRATIONS:
        conn.execute(f.read_text(encoding="utf-8"))
    conn.conninfo_str = conninfo  # para abrir conexiones adicionales
    try:
        yield conn
    finally:
        conn.close()
        admin.execute(f"drop database {name} with (force)")
        admin.close()
