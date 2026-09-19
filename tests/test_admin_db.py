import os
import subprocess
import sys
import uuid
from decimal import Decimal
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg import errors as E  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402

from ape import admin  # noqa: E402
from ape.canon import args_hash  # noqa: E402
from ape.db import load_registry  # noqa: E402
from ape.policy import ActionRequest, Code, Origin, PolicyEngine, PolicyState  # noqa: E402

from helpers import as_agent, role  # noqa: E402

SECRET = bytes.fromhex("aa" * 32)


def propose(agent, tool="payment.execute", args=None, cost=20, hash_=None):
    args = args if args is not None else {"to": "proveedor", "eur": 20}
    return str(agent.execute(
        "insert into ape.action(tool, args, args_hash, cost_eur, origin, idempotency_key) "
        "values (%s, %s, %s, %s, 'agent', %s) returning id",
        (tool, Jsonb(args), hash_ or args_hash(args), cost, uuid.uuid4().hex)).fetchone()[0])


def test_flujo_de_aprobacion_completo(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    aid = propose(agent)
    pend = admin.pending(pgdb)
    assert [(p.id, p.tool, p.cost_eur, p.hash_ok) for p in pend] == [(aid, "payment.execute", Decimal("20.00"), True)]

    ap = admin.approve(pgdb, aid, SECRET)
    assert pgdb.execute("select status from ape.action where id = %s", (aid,)).fetchone()[0] == "aprobada"

    # El ejecutor (con la clave) valida la aprobación con el motor y solo entonces ejecuta.
    engine = PolicyEngine(load_registry(pgdb), SECRET)
    args = pgdb.execute("select args from ape.action where id = %s", (aid,)).fetchone()[0]
    req = ActionRequest(aid, "payment.execute", args, Origin.AGENT, "k", Decimal("20"))
    assert engine.evaluate(req, PolicyState(), ap).allowed
    with role(pgdb, "ape_executor"):
        pgdb.execute("update ape.action set status = 'ejecutada' where id = %s", (aid,))
    assert pgdb.execute("select amount_eur, approved_by from ape.budget_ledger").fetchone() == (Decimal("20.00"), "dani")
    assert admin.pending(pgdb) == []
    agent.close()


def test_no_se_firma_si_el_hash_no_corresponde_a_los_argumentos(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    aid = propose(agent, args={"to": "A", "eur": 20}, hash_=args_hash({"to": "B", "eur": 20}))
    assert admin.pending(pgdb)[0].hash_ok is False
    with pytest.raises(admin.AdminError, match="hash"):
        admin.approve(pgdb, aid, SECRET)
    assert pgdb.execute("select count(*) from ape.approval").fetchone()[0] == 0
    agent.close()


def test_solo_se_aprueba_lo_pendiente_y_n3(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    n0 = propose(agent, tool="memory.search", args={}, cost=0)
    with pytest.raises(admin.AdminError):
        admin.approve(pgdb, n0, SECRET)                       # no es N3
    with pytest.raises(admin.AdminError):
        admin.approve(pgdb, str(uuid.uuid4()), SECRET)        # no existe
    aid = propose(agent)
    admin.approve(pgdb, aid, SECRET)
    with pytest.raises(admin.AdminError):
        admin.approve(pgdb, aid, SECRET)                      # ya aprobada
    agent.close()


def test_rechazar(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    aid = propose(agent)
    admin.reject(pgdb, aid)
    assert pgdb.execute("select status from ape.action where id = %s", (aid,)).fetchone()[0] == "rechazada"
    with pytest.raises(admin.AdminError):
        admin.approve(pgdb, aid, SECRET)
    agent.close()


def test_limites_de_caducidad_y_clave(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    aid = propose(agent)
    for hours in (0, 24 * 7 + 1):
        with pytest.raises(admin.AdminError):
            admin.approve(pgdb, aid, SECRET, hours=hours)
    with pytest.raises(admin.AdminError):
        admin.approve(pgdb, aid, b"")
    agent.close()


def test_el_agente_no_puede_aprobar_por_su_cuenta(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    aid = propose(agent)
    with pytest.raises(E.InsufficientPrivilege):
        admin.approve(agent, aid, SECRET)
    with pytest.raises(E.InsufficientPrivilege):
        admin.kill(agent, "x")
    with pytest.raises(E.InsufficientPrivilege):
        admin.resume(agent)
    agent.close()


def test_parada_y_reanudacion_y_auditoria(pgdb):
    admin.kill(pgdb, "prueba")
    assert pgdb.execute("select active from ape.kill_switch").fetchone()[0] is True
    admin.resume(pgdb)
    assert pgdb.execute("select active from ape.kill_switch").fetchone()[0] is False
    assert admin.audit_verify(pgdb) is None


def test_mensaje_vacio(pgdb):
    with pytest.raises(admin.AdminError):
        admin.say(pgdb, "   ")


# ---------------- la CLI de verdad, como proceso ----------------

def run_cli(pgdb, *args, **extra_env):
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
               APE_DSN_ADMIN=pgdb.conninfo_str, APE_APPROVAL_SECRET="aa" * 32)
    env.update(extra_env)
    return subprocess.run([sys.executable, "-m", "ape.cli", *args], env=env,
                          capture_output=True, text=True, timeout=60)


def test_cli_extremo_a_extremo(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    aid = propose(agent)

    r = run_cli(pgdb, "pending")
    assert r.returncode == 0 and aid in r.stdout and "payment.execute" in r.stdout

    r = run_cli(pgdb, "approve", aid, "--confirm-id", "incorrecto")
    assert r.returncode != 0 and pgdb.execute("select count(*) from ape.approval").fetchone()[0] == 0

    r = run_cli(pgdb, "approve", aid, "--confirm-id", aid[:8])
    assert r.returncode == 0 and "Aprobada" in r.stdout
    assert pgdb.execute("select count(*) from ape.approval").fetchone()[0] == 1

    assert run_cli(pgdb, "say", "hola", "agente").returncode == 0
    assert pgdb.execute("select content, from_dani from ape.inbox").fetchone() == ("hola agente", True)

    r = run_cli(pgdb, "kill", "motivo", "de", "prueba")
    assert r.returncode == 0 and pgdb.execute("select active from ape.kill_switch").fetchone()[0] is True
    assert run_cli(pgdb, "resume").returncode == 0

    r = run_cli(pgdb, "audit-verify")
    assert r.returncode == 0 and "íntegra" in r.stdout
    agent.close()


def test_cli_rechaza_una_clave_corta_o_mal_formada(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    aid = propose(agent)
    for bad in ("zz", "aa" * 4):
        r = run_cli(pgdb, "approve", aid, "--confirm-id", aid[:8], APE_APPROVAL_SECRET=bad)
        assert r.returncode != 0
    assert pgdb.execute("select count(*) from ape.approval").fetchone()[0] == 0
    agent.close()
