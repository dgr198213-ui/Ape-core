import json

import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg import errors as E  # noqa: E402

from ape.db import load_registry  # noqa: E402
from ape.panel import auth  # noqa: E402
from ape.panel.app import COOKIE, PanelConfig, create_app  # noqa: E402
from ape.policy import ActionRequest, Approval, Origin, PolicyEngine, PolicyState  # noqa: E402

from helpers import MockLLM, as_agent, propose_action, role  # noqa: E402
from decimal import Decimal  # noqa: E402

SECRET = bytes.fromhex("bb" * 32)
BASE = "https://panel.test"
PASS = "una frase de paso muy larga"
T0 = 1_800_000_000.0


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t

    def advance(self, s=31):
        self.t += s


class Panel:
    def __init__(self, pgdb, **cfg_kw):
        self.db, self.clock = pgdb, Clock()
        cfg = PanelConfig(dsn="x", approval_secret=SECRET, setup_token="SETUP-TOKEN-1", **cfg_kw)

        def connect():
            c = psycopg.connect(pgdb.conninfo_str, autocommit=True)
            c.execute("set session authorization ape_panel")
            c.execute("set search_path = ape, extensions, public, pg_catalog")
            return c
        self.client = create_app(cfg, connect=connect, clock=self.clock).test_client()
        self.csrf = None
        self.secret = None

    def call(self, method, path, json_body=None, csrf=True, origin=BASE):
        headers = {}
        if origin:
            headers["Origin"] = origin
        if csrf and self.csrf:
            headers["X-CSRF"] = self.csrf
        return self.client.open(path, method=method, json=json_body, headers=headers, base_url=BASE)

    def code(self):
        return auth.hotp(self.secret, auth.current_step(self.clock()))

    def setup(self):
        r = self.call("POST", "/api/setup/start", {"setup_token": "SETUP-TOKEN-1"})
        assert r.status_code == 200, r.json
        self.secret = r.json["totp_secret"]
        r = self.call("POST", "/api/setup/finish", {"setup_token": "SETUP-TOKEN-1", "passphrase": PASS,
                                                    "totp_secret": self.secret, "code": self.code()})
        assert r.status_code == 200, r.json

    def login(self):
        self.clock.advance()
        r = self.call("POST", "/api/login", {"passphrase": PASS, "code": self.code()})
        assert r.status_code == 200, r.json
        self.csrf = self.call("GET", "/api/state").json["csrf"]
        return r

    def fresh_code(self):
        self.clock.advance()
        return self.code()


@pytest.fixture
def panel(pgdb):
    return Panel(pgdb)


@pytest.fixture
def logged(panel):
    panel.setup()
    panel.login()
    return panel


# ---------------------------------------------------------------- configuración inicial

def test_configuracion_inicial(panel):
    assert panel.call("GET", "/api/state").json["setup_needed"] is True
    r = panel.call("POST", "/api/setup/start", {"setup_token": "ERRONEO"})
    assert r.status_code == 403
    panel.setup()
    assert panel.call("GET", "/api/state").json["setup_needed"] is False
    assert panel.call("POST", "/api/setup/start", {"setup_token": "SETUP-TOKEN-1"}).status_code == 409


def test_configuracion_valida_frase_y_codigo(panel):
    secret = panel.call("POST", "/api/setup/start", {"setup_token": "SETUP-TOKEN-1"}).json["totp_secret"]
    code = auth.hotp(secret, auth.current_step(panel.clock()))
    r = panel.call("POST", "/api/setup/finish", {"setup_token": "SETUP-TOKEN-1", "passphrase": "corta",
                                                 "totp_secret": secret, "code": code})
    assert r.status_code == 400
    r = panel.call("POST", "/api/setup/finish", {"setup_token": "SETUP-TOKEN-1", "passphrase": PASS,
                                                 "totp_secret": secret, "code": "000000"})
    assert r.status_code == 400
    assert panel.db.execute("select count(*) from ape.panel_auth").fetchone()[0] == 0


def test_el_codigo_de_configuracion_no_se_puede_forzar(panel):
    for _ in range(5):
        assert panel.call("POST", "/api/setup/start", {"setup_token": "x"}).status_code == 403
    assert panel.call("POST", "/api/setup/start", {"setup_token": "SETUP-TOKEN-1"}).status_code == 429


def test_configuracion_desactivada_sin_codigo_en_el_servidor(pgdb):
    p = Panel(pgdb)
    p.client.application.view_functions  # la app existe
    cfg_sin = PanelConfig(dsn="x", approval_secret=SECRET, setup_token="")
    app = create_app(cfg_sin, connect=lambda: psycopg.connect(pgdb.conninfo_str, autocommit=True))
    r = app.test_client().post("/api/setup/start", json={"setup_token": ""}, base_url=BASE)
    assert r.status_code == 403


# ---------------------------------------------------------------- inicio de sesión

def test_login_correcto_y_atributos_de_la_cookie(panel):
    panel.setup()
    r = panel.login()
    cookie = r.headers.get("Set-Cookie")
    assert cookie.startswith(COOKIE + "=") and COOKIE.startswith("__Host-")
    for attr in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
        assert attr in cookie
    assert "Domain" not in cookie and "Max-Age" in cookie


def test_errores_de_login_no_revelan_cual_dato_falla(panel):
    panel.setup()
    panel.clock.advance()
    a = panel.call("POST", "/api/login", {"passphrase": "mala frase de paso!!", "code": panel.code()})
    panel.clock.advance()
    b = panel.call("POST", "/api/login", {"passphrase": PASS, "code": "000000"})
    assert a.status_code == b.status_code == 401 and a.json == b.json


def test_bloqueo_tras_cinco_fallos_incluso_con_credenciales_correctas(panel):
    panel.setup()
    for _ in range(5):
        panel.call("POST", "/api/login", {"passphrase": "x" * 14, "code": "000000"})
    panel.clock.advance()
    r = panel.call("POST", "/api/login", {"passphrase": PASS, "code": panel.code()})
    assert r.status_code == 429


def test_un_codigo_totp_no_se_puede_reutilizar(panel):
    panel.setup()
    panel.clock.advance()
    code = panel.code()
    assert panel.call("POST", "/api/login", {"passphrase": PASS, "code": code}).status_code == 200
    assert panel.call("POST", "/api/login", {"passphrase": PASS, "code": code}).status_code == 401


def test_la_sesion_se_guarda_hasheada(logged):
    token = logged.client.get_cookie(COOKIE, domain="panel.test").value
    rows = logged.db.execute("select token_hash from ape.panel_session").fetchall()
    assert rows and all(token not in r[0] and r[0] == auth.token_hash(token) for r in rows)


# ---------------------------------------------------------------- protección de la API

@pytest.mark.parametrize("method,path", [("GET", "/api/status"), ("GET", "/api/pending"), ("GET", "/api/audit"),
                                         ("POST", "/api/say"), ("POST", "/api/approve"), ("POST", "/api/reject"),
                                         ("POST", "/api/kill"), ("POST", "/api/resume"), ("POST", "/api/run-cycle"),
                                         ("POST", "/api/logout")])
def test_sin_sesion_todo_devuelve_401(panel, method, path):
    panel.setup()
    assert panel.call(method, path, {}).status_code == 401


def test_csrf_y_origen(logged):
    assert logged.call("POST", "/api/say", {"text": "hola"}, csrf=False).status_code == 403
    logged.csrf = "0" * 64
    assert logged.call("POST", "/api/say", {"text": "hola"}).status_code == 403
    logged.csrf = logged.call("GET", "/api/state").json["csrf"]
    assert logged.call("POST", "/api/say", {"text": "hola"}, origin="https://malo.example").status_code == 403
    assert logged.call("POST", "/api/say", {"text": "hola"}).status_code == 200


def test_caducidad_por_inactividad_y_absoluta(logged):
    logged.db.execute("update ape.panel_session set last_seen = now() - interval '31 minutes'")
    assert logged.call("GET", "/api/status").status_code == 401
    logged.login()
    logged.db.execute("update ape.panel_session set expires_at = now() - interval '1 second'")
    assert logged.call("GET", "/api/status").status_code == 401


def test_cerrar_sesion_la_invalida(logged):
    assert logged.call("POST", "/api/logout", {}).status_code == 200
    assert logged.call("GET", "/api/status").status_code == 401
    assert logged.db.execute("select count(*) from ape.panel_session").fetchone()[0] == 0


# ---------------------------------------------------------------- hablar y estado

def test_say_va_a_la_bandeja_como_dani_y_la_auditoria_no_guarda_el_texto(logged):
    assert logged.call("POST", "/api/say", {"text": "SECRETO-XYZ"}).status_code == 200
    assert logged.db.execute("select content, from_dani, source from ape.inbox").fetchone() == (
        "SECRETO-XYZ", True, "manual_dani")
    canons = " ".join(r[0] for r in logged.db.execute("select canon from ape.audit_event"))
    assert "SECRETO-XYZ" not in canons and "panel.say" in canons
    for bad in ("", "   ", "x" * 4001):
        assert logged.call("POST", "/api/say", {"text": bad}).status_code == 400


def test_estado(logged):
    agent = as_agent(logged.db.conninfo_str)
    propose_action(agent)
    propose_action(agent, tool="memory.write", args={"k": 1}, cost=0)
    agent.execute("insert into ape.audit_event(actor, type, canon) values ('cycle','cycle.end', %s)",
                  (json.dumps({"actor": "cycle", "type": "cycle.end", "payload": {
                      "events": 3, "proposals": 2, "denied": 1, "withheld": 0, "errors": []}}),))
    agent.close()
    s = logged.call("GET", "/api/status").json
    assert s["kill"]["active"] is False and s["pending_approval"] == 1 and s["other_proposals"] == 1
    assert s["last_cycle"]["events"] == 3 and s["last_cycle"]["proposals"] == 2
    assert s["audit_ok"] is True and len(s["audit_head"]) == 64
    assert logged.call("GET", "/api/audit").json[0]["seq"] >= 1


# ---------------------------------------------------------------- aprobar, rechazar, parar

def engine_accepts(db, action_id):
    row = db.execute("select args, cost_eur from ape.action where id = %s", (action_id,)).fetchone()
    a = db.execute("select args_hash, approver, amount_eur, expires_at, signature from ape.approval "
                   "where action_id = %s", (action_id,)).fetchone()
    engine = PolicyEngine(load_registry(db), SECRET)
    req = ActionRequest(action_id, "payment.execute", row[0], Origin.AGENT, "k", row[1])
    return engine.evaluate(req, PolicyState(), Approval(action_id, a[0], a[1], a[2], a[3], a[4])).allowed


def test_aprobar_exige_un_codigo_nuevo_y_produce_una_aprobacion_valida_para_el_ejecutor(logged):
    agent = as_agent(logged.db.conninfo_str)
    aid = propose_action(agent)
    agent.close()
    p = logged.call("GET", "/api/pending").json
    assert [(x["id"], x["hash_ok"], x["cost_eur"]) for x in p] == [(aid, True, "20.00")]

    assert logged.call("POST", "/api/approve", {"id": aid}).status_code == 403            # sin código
    assert logged.call("POST", "/api/approve", {"id": aid, "code": "000000"}).status_code == 403
    r = logged.call("POST", "/api/approve", {"id": aid, "code": logged.fresh_code()})
    assert r.status_code == 200, r.json
    assert logged.db.execute("select status from ape.action where id = %s", (aid,)).fetchone()[0] == "aprobada"
    assert engine_accepts(logged.db, aid)                                                # el ejecutor la acepta
    assert logged.call("GET", "/api/pending").json == []


def test_un_codigo_usado_no_sirve_para_una_segunda_aprobacion(logged):
    agent = as_agent(logged.db.conninfo_str)
    a1, a2 = propose_action(agent), propose_action(agent, args={"to": "otro", "eur": 5}, cost=5)
    agent.close()
    code = logged.fresh_code()
    assert logged.call("POST", "/api/approve", {"id": a1, "code": code}).status_code == 200
    assert logged.call("POST", "/api/approve", {"id": a2, "code": code}).status_code == 403


def test_no_aprueba_si_el_hash_no_corresponde(logged):
    from ape.canon import args_hash
    agent = as_agent(logged.db.conninfo_str)
    aid = propose_action(agent, args={"to": "A", "eur": 20}, hash_=args_hash({"to": "B", "eur": 20}))
    agent.close()
    assert logged.call("GET", "/api/pending").json[0]["hash_ok"] is False
    r = logged.call("POST", "/api/approve", {"id": aid, "code": logged.fresh_code()})
    assert r.status_code == 409
    assert logged.db.execute("select count(*) from ape.approval").fetchone()[0] == 0


def test_rechazar_y_acciones_inexistentes(logged):
    agent = as_agent(logged.db.conninfo_str)
    aid = propose_action(agent)
    agent.close()
    assert logged.call("POST", "/api/reject", {"id": aid}).status_code == 200
    assert logged.db.execute("select status from ape.action where id = %s", (aid,)).fetchone()[0] == "rechazada"
    assert logged.call("POST", "/api/reject", {"id": aid}).status_code == 409
    assert logged.call("POST", "/api/approve", {"id": "no-existe", "code": logged.fresh_code()}).status_code == 409


def test_los_intentos_de_codigo_erroneos_se_bloquean(logged):
    for _ in range(5):
        assert logged.call("POST", "/api/approve", {"id": "x", "code": "000000"}).status_code == 403
    assert logged.call("POST", "/api/approve", {"id": "x", "code": logged.fresh_code()}).status_code == 429


def test_parar_es_inmediato_y_reanudar_exige_codigo(logged):
    assert logged.call("POST", "/api/kill", {"reason": "prueba"}).status_code == 200
    assert logged.db.execute("select active from ape.kill_switch").fetchone()[0] is True
    assert logged.call("POST", "/api/resume", {}).status_code == 403
    assert logged.db.execute("select active from ape.kill_switch").fetchone()[0] is True
    assert logged.call("POST", "/api/resume", {"code": logged.fresh_code()}).status_code == 200
    assert logged.db.execute("select active from ape.kill_switch").fetchone()[0] is False
    types = {r[0] for r in logged.db.execute("select type from ape.audit_event")}
    assert {"panel.kill", "panel.resume", "panel.login", "panel.setup"} <= types


# ---------------------------------------------------------------- lanzar el ciclo

def test_lanzar_ciclo_llama_a_github_sin_filtrar_el_token(pgdb):
    gh = MockLLM(status=204)
    try:
        p = Panel(pgdb, github_token="TOKEN-GH-SECRETO", github_repo="dani/ape-core", github_api=gh.base_url)
        p.setup(); p.login()
        assert p.call("GET", "/api/state").json["can_run_cycle"] is True
        r = p.call("POST", "/api/run-cycle", {})
        assert r.status_code == 200 and "TOKEN-GH" not in r.get_data(as_text=True)
        req = gh.requests[0]
        assert req["path"] == "/repos/dani/ape-core/actions/workflows/cycle.yml/dispatches"
        assert req["headers"]["Authorization"] == "Bearer TOKEN-GH-SECRETO" and req["body"] == {"ref": "main"}
        canons = " ".join(x[0] for x in pgdb.execute("select canon from ape.audit_event"))
        assert "TOKEN-GH" not in canons
    finally:
        gh.close()


def test_lanzar_ciclo_no_configurado(logged):
    assert logged.call("POST", "/api/run-cycle", {}).status_code == 501


def test_lanzar_ciclo_con_error_de_github(pgdb):
    gh = MockLLM(status=500)
    try:
        p = Panel(pgdb, github_token="t", github_repo="a/b", github_api=gh.base_url)
        p.setup(); p.login()
        assert p.call("POST", "/api/run-cycle", {}).status_code == 502
    finally:
        gh.close()


# ---------------------------------------------------------------- cabeceras y estáticos

def test_cabeceras_de_seguridad_y_estaticos(panel):
    r = panel.call("GET", "/")
    assert r.status_code == 200 and b"/app.js" in r.data
    csp = r.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "frame-ancestors 'none'" in csp
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert panel.call("GET", "/api/state").headers["Cache-Control"] == "no-store"
    for name, ctype in (("app.js", "javascript"), ("app.css", "css"), ("manifest.webmanifest", "manifest"),
                        ("sw.js", "javascript"), ("icon.svg", "svg")):
        rr = panel.call("GET", "/" + name)
        assert rr.status_code == 200 and ctype in rr.headers["Content-Type"], name
    for bad in ("/app.py", "/..%2Fapp.py", "/__init__.py", "/static/../app.py"):
        assert panel.call("GET", bad).status_code == 404


def test_el_javascript_no_usa_innerhtml_ni_eval():
    import pathlib
    js = (pathlib.Path(__file__).resolve().parents[1] / "src/ape/panel/static/app.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert forbidden not in js


# ---------------------------------------------------------------- privilegios del rol de BD

@pytest.mark.parametrize("sql", [
    "update ape.core_policy set value = '\"otro\"'::jsonb where key = 'approver'",
    "insert into ape.tool_spec(name, level) values ('x', 0)",
    "update ape.tool_spec set level = 0 where name = 'payment.execute'",
    "select * from ape.memory",
    "insert into ape.budget_ledger(action_id, amount_eur, approved_by) values (gen_random_uuid(), 1, 'x')",
    "update ape.audit_event set canon = 'x'",
    "delete from ape.audit_event",
    "insert into ape.action(tool, args, args_hash, origin, idempotency_key) values ('memory.search','{}','h','dani','k')",
    "update ape.action set cost_eur = 0",
    "update ape.action set args = '{}'::jsonb",
    "delete from ape.approval",
    "delete from ape.inbox",
])
def test_el_rol_del_panel_no_puede(pgdb, sql):
    with role(pgdb, "ape_panel"):
        with pytest.raises((E.InsufficientPrivilege, E.CheckViolation)):
            pgdb.execute(sql)


def test_el_panel_no_puede_marcar_acciones_como_ejecutadas(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    aid = propose_action(agent, tool="memory.search", args={}, cost=0)
    agent.close()
    with role(pgdb, "ape_panel"):
        with pytest.raises(E.InsufficientPrivilege, match="solo puede aprobar o rechazar"):
            pgdb.execute("update ape.action set status = 'ejecutada' where id = %s", (aid,))
        pgdb.execute("update ape.action set status = 'rechazada' where id = %s", (aid,))


def test_ni_el_agente_ni_el_ejecutor_leen_las_credenciales_del_panel(logged):
    for who in ("ape_agent", "ape_executor"):
        with role(logged.db, who):
            for table in ("panel_auth", "panel_session", "panel_attempt"):
                with pytest.raises(E.InsufficientPrivilege):
                    logged.db.execute(f"select * from ape.{table}")


def test_la_configuracion_exige_una_clave_de_aprobacion_larga(monkeypatch):
    monkeypatch.setenv("APE_PANEL_DSN", "postgresql://x")
    monkeypatch.setenv("APE_APPROVAL_SECRET", "aa" * 8)
    with pytest.raises(ValueError):
        PanelConfig.from_env()
    monkeypatch.setenv("APE_APPROVAL_SECRET", "aa" * 32)
    assert PanelConfig.from_env().approval_secret == bytes.fromhex("aa" * 32)
    monkeypatch.setenv("APE_APPROVAL_SECRET", "Zk3-p9Q_una cadena cualquiera de un gestor 8842")
    assert PanelConfig.from_env().approval_secret == "Zk3-p9Q_una cadena cualquiera de un gestor 8842".encode()
