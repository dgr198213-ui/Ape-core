"""Pruebas de integración contra un PostgreSQL real (con pgvector).

Se activan definiendo APE_TEST_DSN con un usuario superusuario, por ejemplo:
  APE_TEST_DSN=postgresql://postgres:test@127.0.0.1:5432/postgres pytest tests/test_db.py
Cada prueba crea una base de datos nueva, aplica las migraciones y la borra al terminar.
"""
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg import errors as E  # noqa: E402
from psycopg.conninfo import make_conninfo  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402

from ape.audit import AuditRow, verify_chain  # noqa: E402
from ape.canon import args_hash  # noqa: E402
from ape.policy import (ActionRequest, Approval, Code, Level, Origin, PolicyEngine,  # noqa: E402
                        PolicyState, ToolRegistry, ToolSpec, sign_approval)

DSN = os.environ.get("APE_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="APE_TEST_DSN no definido")
MIGRATIONS = sorted((Path(__file__).resolve().parents[1] / "migrations").glob("*.sql"))
SECRET = b"clave-de-aprobaciones-fuera-de-la-bd"


@pytest.fixture
def db():
    admin = psycopg.connect(DSN, autocommit=True)
    name = "ape_t_" + uuid.uuid4().hex[:8]
    admin.execute(f"create database {name}")
    conn = psycopg.connect(make_conninfo(DSN, dbname=name), autocommit=True)
    for f in MIGRATIONS:
        conn.execute(f.read_text(encoding="utf-8"))
    try:
        yield conn
    finally:
        conn.close()
        admin.execute(f"drop database {name} with (force)")
        admin.close()


@contextmanager
def role(conn, name):
    conn.execute(f"set session authorization {name}")
    try:
        yield conn
    finally:
        conn.execute("reset session authorization")


def propose(conn, tool, args=None, cost=0, origin="agent", key=None):
    args = args if args is not None else {"k": 1}
    row = conn.execute(
        "insert into ape.action(tool, args, args_hash, cost_eur, origin, idempotency_key) "
        "values (%s, %s, %s, %s, %s, %s) returning id, level, involves_money, status, args_hash",
        (tool, Jsonb(args), args_hash(args), cost, origin, key or uuid.uuid4().hex)).fetchone()
    return {"id": row[0], "level": row[1], "money": row[2], "status": row[3], "hash": row[4]}


def approve(conn, action, amount, approver="dani", hours=1, ahash=None):
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    ahash = ahash or action["hash"]
    sig = sign_approval(SECRET, str(action["id"]), ahash, approver, Decimal(amount), expires)
    conn.execute(
        "insert into ape.approval(action_id, args_hash, approver, amount_eur, expires_at, signature) "
        "values (%s, %s, %s, %s, %s, %s)", (action["id"], ahash, approver, amount, expires, sig))
    return Approval(str(action["id"]), ahash, approver, Decimal(amount), expires, sig)


def set_status(conn, action, status):
    conn.execute("update ape.action set status = %s where id = %s", (status, action["id"]))


def audit_rows(conn):
    return [AuditRow(*r) for r in conn.execute(
        "select seq, ts_utc, db_role, canon, prev_hash, hash from ape.audit_event order by seq")]


# ---------------- permisos: el agente no toca el núcleo ----------------

@pytest.mark.parametrize("sql", [
    "update ape.core_policy set value = '\"agente\"' where key = 'approver'",
    "delete from ape.core_policy",
    "insert into ape.tool_spec(name, level) values ('x', 0)",
    "update ape.tool_spec set level = 0 where name = 'payment.execute'",
    "update ape.kill_switch set active = false",
    "select ape.kill('x')",
    "select ape.resume()",
    "insert into ape.goal(name, definition) values ('x', '{}')",
])
@pytest.mark.parametrize("who", ["ape_agent", "ape_executor"])
def test_agente_y_ejecutor_no_modifican_el_nucleo(db, who, sql):
    with role(db, who):
        with pytest.raises(E.InsufficientPrivilege):
            db.execute(sql)


def test_agente_no_puede_aprobar_ni_tocar_el_libro_de_gasto(db):
    with role(db, "ape_agent"):
        a = propose(db, "payment.execute", cost=5)
    for who in ("ape_agent", "ape_executor"):
        with role(db, who):
            with pytest.raises(E.InsufficientPrivilege):
                db.execute("insert into ape.approval(action_id, args_hash, approver, amount_eur, "
                           "expires_at, signature) values (%s,'h','dani',5, now()+interval '1 hour','s')",
                           (a["id"],))
            with pytest.raises(E.InsufficientPrivilege):
                db.execute("insert into ape.budget_ledger(action_id, amount_eur, approved_by) "
                           "values (%s, 5, 'dani')", (a["id"],))


def test_el_agente_no_puede_modificar_acciones(db):
    with role(db, "ape_agent"):
        a = propose(db, "memory.write")
        with pytest.raises(E.InsufficientPrivilege):
            set_status(db, a, "ejecutada")


def test_el_ejecutor_solo_puede_cambiar_el_estado(db):
    with role(db, "ape_agent"):
        a = propose(db, "message.send")
    with role(db, "ape_executor"):
        with pytest.raises(E.InsufficientPrivilege):
            db.execute("update ape.action set args = '{}'::jsonb where id = %s", (a["id"],))
        with pytest.raises(E.InsufficientPrivilege):
            db.execute("update ape.action set cost_eur = 0 where id = %s", (a["id"],))


# ---------------- clasificación de acciones ----------------

def test_el_nivel_lo_fija_el_registro_no_quien_propone(db):
    with role(db, "ape_agent"):
        pay = propose(db, "payment.execute", cost=0)
        cheap = propose(db, "memory.search", cost=Decimal("0.01"))   # N0 que pretende costar
        safe = propose(db, "memory.search")
    assert pay["level"] == 3 and pay["money"] is True
    assert cheap["level"] == 3 and cheap["money"] is True
    assert safe["level"] == 0 and safe["money"] is False


def test_el_agente_no_puede_proponer_ya_ejecutada(db):
    with role(db, "ape_agent"):
        row = db.execute(
            "insert into ape.action(tool, args, args_hash, origin, idempotency_key, status) "
            "values ('memory.write','{}','h','agent','k-forzada','ejecutada') returning status").fetchone()
    assert row[0] == "propuesta"


def test_herramienta_desconocida_o_deshabilitada(db):
    with role(db, "ape_agent"):
        with pytest.raises(E.CheckViolation):
            propose(db, "hack.everything")
    db.execute("update ape.tool_spec set enabled = false where name = 'message.send'")
    with role(db, "ape_agent"):
        with pytest.raises(E.CheckViolation):
            propose(db, "message.send")


def test_idempotencia_unica(db):
    with role(db, "ape_agent"):
        propose(db, "memory.write", key="misma")
        with pytest.raises(E.UniqueViolation):
            propose(db, "memory.write", key="misma")


# ---------------- ejecución, aprobaciones y dinero ----------------

def test_n0_se_ejecuta_sin_aprobacion(db):
    with role(db, "ape_agent"):
        a = propose(db, "memory.search")
    with role(db, "ape_executor"):
        set_status(db, a, "ejecutada")
    assert db.execute("select status, executed_at is not null from ape.action where id=%s",
                      (a["id"],)).fetchone() == ("ejecutada", True)


def test_n3_sin_aprobacion_no_se_ejecuta(db):
    with role(db, "ape_agent"):
        a = propose(db, "payment.execute", cost=10)
    with role(db, "ape_executor"):
        with pytest.raises(E.InsufficientPrivilege):
            set_status(db, a, "ejecutada")


def test_n3_con_aprobacion_se_ejecuta_y_queda_en_el_libro(db):
    with role(db, "ape_agent"):
        a = propose(db, "payment.execute", args={"to": "X", "eur": 10}, cost=10)
    approve(db, a, 10)
    with role(db, "ape_executor"):
        set_status(db, a, "ejecutada")
    assert db.execute("select amount_eur, approved_by from ape.budget_ledger").fetchall() == [
        (Decimal("10.00"), "dani")]


def test_aprobacion_invalida_se_rechaza_en_la_bd(db):
    with role(db, "ape_agent"):
        a = propose(db, "payment.execute", cost=10)
    with pytest.raises(E.InsufficientPrivilege):
        approve(db, a, 10, approver="agente")            # aprobador no autorizado
    with pytest.raises(E.InsufficientPrivilege):
        approve(db, a, 10, ahash="otro-hash")            # otros argumentos
    with pytest.raises(E.InsufficientPrivilege):
        approve(db, a, 9.99)                             # importe menor que el coste
    with pytest.raises(E.CheckViolation):
        approve(db, a, 10, hours=24 * 8)                 # caducidad excesiva
    with role(db, "ape_executor"):
        with pytest.raises(E.InsufficientPrivilege):
            set_status(db, a, "ejecutada")


def test_una_aprobacion_no_se_puede_modificar_ni_borrar(db):
    with role(db, "ape_agent"):
        a = propose(db, "payment.execute", cost=10)
    approve(db, a, 10)
    with pytest.raises(E.InsufficientPrivilege):
        db.execute("update ape.approval set amount_eur = 9999")
    with pytest.raises(E.InsufficientPrivilege):
        db.execute("delete from ape.approval")


def test_transiciones_de_estado_validas(db):
    with role(db, "ape_agent"):
        a = propose(db, "memory.write")
    with role(db, "ape_executor"):
        set_status(db, a, "ejecutada")
        with pytest.raises(E.CheckViolation):
            set_status(db, a, "propuesta")
        set_status(db, a, "revertida")
        with pytest.raises(E.CheckViolation):
            set_status(db, a, "ejecutada")


# ---------------- parada ----------------

def test_parada_bloquea_toda_ejecucion_y_se_puede_reanudar(db):
    with role(db, "ape_agent"):
        a = propose(db, "memory.search")
        b = propose(db, "memory.search")
    db.execute("select ape.kill('prueba')")
    with role(db, "ape_executor"):
        with pytest.raises(E.InsufficientPrivilege):
            set_status(db, a, "ejecutada")
    db.execute("select ape.resume()")
    with role(db, "ape_executor"):
        set_status(db, b, "ejecutada")


# ---------------- estrategias ----------------

def test_el_agente_no_puede_promover_estrategias(db):
    with role(db, "ape_agent"):
        row = db.execute("insert into ape.strategy(genome, status) values ('{}', 'activa') "
                         "returning id, status").fetchone()
        assert row[1] == "sombra"
        with pytest.raises(E.InsufficientPrivilege):
            db.execute("update ape.strategy set status = 'activa' where id = %s", (row[0],))
    db.execute("update ape.strategy set status = 'activa' where id = %s", (row[0],))  # Dani sí


def test_la_memoria_falla_cerrado_en_sensibilidad(db):
    with role(db, "ape_agent"):
        row = db.execute("insert into ape.memory(kind, content, source) "
                         "values ('semantica','dato','test') returning sensitivity").fetchone()
    assert row[0] == 2


def test_busqueda_vectorial_funciona(db):
    vec = "[" + ",".join(["0.1"] * 768) + "]"
    with role(db, "ape_agent"):
        db.execute("set search_path = ape, extensions, public, pg_catalog")  # como en el rol real
        db.execute("insert into ape.memory(kind, content, source, sensitivity, embedding) "
                   "values ('semantica','a','t',0,%s::vector)", (vec,))
        row = db.execute("select content from ape.memory order by embedding <=> %s::vector limit 1",
                         (vec,)).fetchone()
    assert row == ("a",)


def test_todas_las_funciones_tienen_search_path_fijo(db):
    n = db.execute(
        "select count(*) from pg_proc where pronamespace = 'ape'::regnamespace and not exists "
        "(select 1 from unnest(coalesce(proconfig, '{}')) c where c like 'search_path=%')").fetchone()[0]
    assert n == 0


def test_pgvector_no_esta_en_public(db):
    assert db.execute("select extnamespace::regnamespace::text from pg_extension "
                      "where extname = 'vector'").fetchone()[0] == "extensions"


# ---------------- auditoría ----------------

def test_la_auditoria_no_se_puede_modificar_ni_por_el_propietario(db):
    with role(db, "ape_agent"):
        db.execute("insert into ape.audit_event(actor, type, canon) values ('agente','t','{}')")
    for stmt in ("update ape.audit_event set canon = 'x'", "delete from ape.audit_event",
                 "truncate ape.audit_event"):
        with pytest.raises(E.InsufficientPrivilege):
            db.execute(stmt)
    with role(db, "ape_agent"):
        with pytest.raises(E.InsufficientPrivilege):
            db.execute("update ape.audit_event set canon = 'x'")


def test_no_se_puede_falsificar_la_cadena_desde_el_cliente(db):
    with role(db, "ape_agent"):
        db.execute("insert into ape.audit_event(seq, actor, type, db_role, ts_utc, canon, prev_hash, hash) "
                   "values (999, 'dani', 'aprobacion', 'dani', '2020-01-01T00:00:00.000000Z', "
                   "'{\"falso\":true}', 'fake', 'fake')")
    row = db.execute("select seq, db_role, ts_utc <> '2020-01-01T00:00:00.000000Z', prev_hash <> 'fake' "
                     "from ape.audit_event order by seq desc limit 1").fetchone()
    assert row[0] != 999 and row[1] == "ape_agent" and row[2] and row[3]
    assert db.execute("select ape.audit_verify()").fetchone()[0] is None


def test_los_cambios_de_politica_quedan_auditados(db):
    db.execute("update ape.core_policy set value = '\"otra-persona\"' where key = 'approver'")
    db.execute("update ape.tool_spec set enabled = false where name = 'message.send'")
    db.execute("select ape.kill('x')")
    types = {r[0] for r in db.execute("select type from ape.audit_event")}
    assert {"core_policy.update", "tool_spec.update", "kill_switch.update"} <= types


def test_cadena_sql_y_python_coinciden_y_detectan_manipulacion(db):
    with role(db, "ape_agent"):
        a = propose(db, "memory.write")
        propose(db, "message.send")
    with role(db, "ape_executor"):
        set_status(db, a, "ejecutada")
    rows = audit_rows(db)
    assert len(rows) >= 4
    assert db.execute("select ape.audit_verify()").fetchone()[0] is None
    assert verify_chain(rows) is None                       # Python recalcula lo que calculó la BD

    # Un propietario decidido puede desactivar el trigger; la verificación lo delata igualmente.
    target = rows[2].seq
    db.execute("alter table ape.audit_event disable trigger audit_no_update_delete")
    db.execute("update ape.audit_event set canon = '{\"manipulado\":1}' where seq = %s", (target,))
    assert db.execute("select ape.audit_verify()").fetchone()[0] == target
    assert verify_chain(audit_rows(db)) == target


# ---------------- extremo a extremo: motor de políticas + base de datos ----------------

def test_flujo_completo_agente_motor_aprobacion_ejecutor(db):
    registry = ToolRegistry([ToolSpec(n, Level(l), bool(m), bool(r)) for n, l, m, r in db.execute(
        "select name, level, involves_money, reversible from ape.tool_spec where enabled")])
    engine = PolicyEngine(registry, SECRET)
    args = {"to": "proveedor", "eur": 25}

    with role(db, "ape_agent"):
        a = propose(db, "payment.execute", args=args, cost=25)
    req = ActionRequest(str(a["id"]), "payment.execute", args, Origin.AGENT, "k", Decimal("25"))

    assert engine.evaluate(req, PolicyState()).code == Code.NEEDS_APPROVAL

    ap = approve(db, a, 25)                                   # Dani firma y aprueba
    decision = engine.evaluate(req, PolicyState(), ap)
    assert decision.allowed

    with role(db, "ape_executor"):
        set_status(db, a, "ejecutada")

    # Si el agente cambia los argumentos después, el motor lo rechaza.
    tampered = ActionRequest(str(a["id"]), "payment.execute", {"to": "OTRO", "eur": 25},
                             Origin.AGENT, "k", Decimal("25"))
    assert engine.evaluate(tampered, PolicyState(), ap).code == Code.BAD_APPROVAL
    assert db.execute("select ape.audit_verify()").fetchone()[0] is None
