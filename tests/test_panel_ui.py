"""Prueba de humo de la interfaz móvil: jsdom + servidor real + PostgreSQL real."""
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")
from werkzeug.serving import make_server  # noqa: E402

from ape.panel.app import COOKIE  # noqa: E402

from helpers import as_agent, propose_action  # noqa: E402
from test_panel_db import Panel  # noqa: E402

UI = Path(__file__).resolve().parent / "ui"
pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not (UI / "node_modules" / "jsdom").exists(),
    reason="hace falta node y `npm install` en tests/ui")


def test_interfaz_extremo_a_extremo(pgdb):
    p = Panel(pgdb)
    p.setup()
    p.login()
    token = p.client.get_cookie(COOKIE, domain="panel.test").value
    agent = as_agent(pgdb.conninfo_str)
    propose_action(agent, args={"note": "<img src=x onerror=window.__pwned=1>", "to": "p", "eur": 20},
                   origin="external_content")
    agent.close()
    approve_code = p.fresh_code()

    srv = make_server("127.0.0.1", 0, p.client.application, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = subprocess.run(["node", "smoke.mjs", f"http://127.0.0.1:{srv.server_address[1]}", token, approve_code],
                           cwd=UI, capture_output=True, text=True, timeout=90)
    finally:
        srv.shutdown()
    assert r.returncode == 0 and "UI OK" in r.stdout, r.stdout + r.stderr
    assert pgdb.execute("select count(*) from ape.approval").fetchone()[0] == 1
    assert pgdb.execute("select active from ape.kill_switch").fetchone()[0] is True
