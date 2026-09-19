"""Panel web de Dani.

Modelo de amenaza: quien controle este proceso puede aprobar lo que el agente haya PROPUESTO y
pulsar la parada; no puede cambiar políticas, herramientas ni ejecutar nada (lo impide el rol de BD
`ape_panel`). Aun así el acceso se protege con frase de paso + TOTP de un solo uso, y toda
aprobación exige un código nuevo.
"""
from __future__ import annotations

import hmac
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

import psycopg
from flask import Flask, Response, g, jsonify, request, send_from_directory

from .. import admin
from ..canon import secret_bytes
from . import auth

COOKIE = "__Host-ape_session"
SESSION_ABSOLUTE_S = 12 * 3600
SESSION_IDLE_S = 30 * 60
MAX_FAILS = 5
LOCK_WINDOW_S = 15 * 60
STATIC = Path(__file__).parent / "static"
STATIC_FILES = {"app.js": "text/javascript", "app.css": "text/css", "icon.svg": "image/svg+xml",
                "sw.js": "text/javascript", "manifest.webmanifest": "application/manifest+json"}

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
       "form-action 'self'")


@dataclass(frozen=True)
class PanelConfig:
    dsn: str
    approval_secret: bytes
    setup_token: str
    github_token: str = ""
    github_repo: str = ""            # "usuario/repositorio"
    github_workflow: str = "cycle.yml"
    github_api: str = "https://api.github.com"
    secure_cookies: bool = True

    @staticmethod
    def from_env() -> "PanelConfig":
        secret = secret_bytes(os.environ["APE_APPROVAL_SECRET"])
        return PanelConfig(
            dsn=os.environ["APE_PANEL_DSN"], approval_secret=secret,
            setup_token=os.environ.get("APE_SETUP_TOKEN", ""),
            github_token=os.environ.get("APE_GITHUB_TOKEN", ""),
            github_repo=os.environ.get("APE_GITHUB_REPO", ""),
            github_workflow=os.environ.get("APE_GITHUB_WORKFLOW", "cycle.yml"))


def create_app(cfg: PanelConfig, connect: Optional[Callable[[], "psycopg.Connection"]] = None,
               clock: Callable[[], float] = time.time) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

    def _connect():
        if connect:
            return connect()
        return psycopg.connect(cfg.dsn, autocommit=True, prepare_threshold=None)  # compatible con el pooler

    def conn():
        if "conn" not in g:
            g.conn = _connect()
        return g.conn

    @app.teardown_appcontext
    def _close(_exc):
        c = g.pop("conn", None)
        if c is not None:
            c.close()

    # ------------------------------------------------------------------ utilidades
    def err(msg: str, status: int):
        return jsonify({"error": msg}), status

    def client_ip() -> str:
        fwd = request.headers.get("x-forwarded-for", "")
        return (fwd.split(",")[0].strip() or request.remote_addr or "")[:64]

    def audit(kind: str, payload: dict) -> None:
        conn().execute("select ape._audit(%s, %s::jsonb)", (kind, json.dumps(payload)))

    def fails(kind: str) -> int:
        return conn().execute(
            "select count(*) from ape.panel_attempt where kind = %s and not ok "
            "and ts > now() - make_interval(secs => %s)", (kind, LOCK_WINDOW_S)).fetchone()[0]

    def note(kind: str, ok: bool) -> None:
        conn().execute("insert into ape.panel_attempt(kind, ok, ip) values (%s, %s, %s)",
                       (kind, ok, client_ip()))
        conn().execute("delete from ape.panel_attempt where ts < now() - interval '2 days'")

    def origin_ok() -> bool:
        origin = request.headers.get("Origin")
        if not origin:
            return True
        return urlparse(origin).netloc == request.host

    def auth_row():
        return conn().execute(
            "select pass_hash, pass_salt, totp_secret, totp_last_step from ape.panel_auth").fetchone()

    def use_totp(code: str, row) -> bool:
        """Consume el código de forma atómica: cada código sirve una sola vez."""
        step = auth.find_totp_step(row[2], code, row[3], clock())
        if step is None:
            return False
        got = conn().execute("update ape.panel_auth set totp_last_step = %s where totp_last_step < %s "
                             "returning 1", (step, step)).fetchone()
        return got is not None

    def start_session(resp: Response) -> None:
        token = auth.new_token()
        conn().execute("insert into ape.panel_session(token_hash, expires_at) values "
                       "(%s, now() + make_interval(secs => %s))", (auth.token_hash(token), SESSION_ABSOLUTE_S))
        conn().execute("delete from ape.panel_session where expires_at < now()")
        resp.set_cookie(COOKIE, token, max_age=SESSION_ABSOLUTE_S, secure=cfg.secure_cookies,
                        httponly=True, samesite="Strict", path="/")

    def session_token() -> Optional[str]:
        token = request.cookies.get(COOKIE)
        if not token:
            return None
        row = conn().execute(
            "update ape.panel_session set last_seen = now() where token_hash = %s and expires_at > now() "
            "and last_seen > now() - make_interval(secs => %s) returning 1",
            (auth.token_hash(token), SESSION_IDLE_S)).fetchone()
        return token if row else None

    def guarded(f):
        """Exige sesión válida, Origin coherente y cabecera CSRF en las peticiones que escriben."""
        @wraps(f)
        def wrapper(*a, **kw):
            token = session_token()
            if token is None:
                return err("sesión no válida", 401)
            if request.method == "POST":
                if not origin_ok() or not hmac.compare_digest(request.headers.get("X-CSRF", ""),
                                                              auth.csrf_for(token)):
                    return err("petición no permitida", 403)
            g.token = token
            return f(*a, **kw)
        return wrapper

    def body() -> dict:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------ cabeceras
    @app.after_request
    def headers(resp: Response):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["X-Robots-Tag"] = "noindex, nofollow"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------------ estáticos
    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html", mimetype="text/html")

    @app.get("/<name>")
    def static_file(name: str):
        if name not in STATIC_FILES:
            return err("no encontrado", 404)
        resp = send_from_directory(STATIC, name, mimetype=STATIC_FILES[name])
        if name == "sw.js":
            resp.headers["Service-Worker-Allowed"] = "/"
        return resp

    # ------------------------------------------------------------------ acceso
    @app.get("/api/state")
    def state():
        setup_needed = auth_row() is None
        token = session_token()
        return jsonify({"setup_needed": setup_needed, "authenticated": token is not None,
                        "csrf": auth.csrf_for(token) if token else None,
                        "can_run_cycle": bool(cfg.github_token and cfg.github_repo)})

    @app.post("/api/setup/start")
    def setup_start():
        if not origin_ok():
            return err("petición no permitida", 403)
        if auth_row() is not None:
            return err("ya configurado", 409)
        if fails("setup") >= MAX_FAILS:
            return err("demasiados intentos", 429)
        d = body()
        if not cfg.setup_token or not hmac.compare_digest(str(d.get("setup_token", "")), cfg.setup_token):
            note("setup", False)
            return err("código de configuración incorrecto", 403)
        secret = auth.new_totp_secret()
        return jsonify({"totp_secret": secret, "otpauth": auth.otpauth_uri(secret)})

    @app.post("/api/setup/finish")
    def setup_finish():
        if not origin_ok():
            return err("petición no permitida", 403)
        if auth_row() is not None:
            return err("ya configurado", 409)
        if fails("setup") >= MAX_FAILS:
            return err("demasiados intentos", 429)
        d = body()
        if not cfg.setup_token or not hmac.compare_digest(str(d.get("setup_token", "")), cfg.setup_token):
            note("setup", False)
            return err("código de configuración incorrecto", 403)
        passphrase, secret = str(d.get("passphrase", "")), str(d.get("totp_secret", ""))
        if len(passphrase) < auth.MIN_PASSPHRASE:
            return err(f"la frase de paso necesita al menos {auth.MIN_PASSPHRASE} caracteres", 400)
        try:
            step = auth.find_totp_step(secret, str(d.get("code", "")), 0, clock())
        except Exception:
            step = None
        if step is None:
            note("setup", False)
            return err("el código de la app no coincide", 400)
        h, salt = auth.hash_passphrase(passphrase)
        conn().execute("insert into ape.panel_auth(pass_hash, pass_salt, totp_secret, totp_last_step) "
                       "values (%s, %s, %s, %s) on conflict do nothing", (h, salt, secret, step))
        audit("panel.setup", {})
        return jsonify({"ok": True})

    @app.post("/api/login")
    def login():
        if not origin_ok():
            return err("petición no permitida", 403)
        if fails("login") >= MAX_FAILS:
            return err("demasiados intentos; espera unos minutos", 429)
        row = auth_row()
        if row is None:
            return err("panel sin configurar", 409)
        d = body()
        pw_ok = auth.verify_passphrase(str(d.get("passphrase", "")), row[0], row[1])
        code_ok = use_totp(str(d.get("code", "")), row)      # se evalúan ambos siempre
        if not (pw_ok and code_ok):
            note("login", False)
            audit("panel.login_failed", {"ip": client_ip()})
            return err("credenciales incorrectas", 401)
        note("login", True)
        audit("panel.login", {"ip": client_ip()})
        resp = jsonify({"ok": True})
        start_session(resp)
        return resp

    @app.post("/api/logout")
    @guarded
    def logout():
        conn().execute("delete from ape.panel_session where token_hash = %s", (auth.token_hash(g.token),))
        resp = jsonify({"ok": True})
        resp.delete_cookie(COOKIE, path="/", secure=cfg.secure_cookies, httponly=True, samesite="Strict")
        return resp

    # ------------------------------------------------------------------ lectura
    @app.get("/api/status")
    @guarded
    def status():
        c = conn()
        kill = c.execute("select active, reason, changed_at from ape.kill_switch").fetchone()
        pending = c.execute("select count(*) from ape.action where status = 'propuesta' and level = 3").fetchone()[0]
        other = c.execute("select count(*) from ape.action where status = 'propuesta' and level < 3").fetchone()[0]
        inbox = c.execute("select count(*) from ape.inbox where processed_at is null").fetchone()[0]
        last = c.execute("select ts_utc, canon from ape.audit_event where type = 'cycle.end' "
                         "order by seq desc limit 1").fetchone()
        last_cycle = None
        if last:
            payload = json.loads(last[1]).get("payload", {})
            last_cycle = {"at": last[0], **{k: payload.get(k) for k in
                          ("events", "proposals", "denied", "withheld", "errors")}}
        bad = admin.audit_verify(c)
        head = c.execute("select hash from ape.audit_event order by seq desc limit 1").fetchone()
        return jsonify({"kill": {"active": kill[0], "reason": kill[1], "since": kill[2].isoformat()},
                        "pending_approval": pending, "other_proposals": other, "inbox_waiting": inbox,
                        "last_cycle": last_cycle, "audit_ok": bad is None, "audit_broken_at": bad,
                        "audit_head": head[0] if head else None})

    @app.get("/api/pending")
    @guarded
    def pending():
        items = admin.pending(conn())
        return jsonify([{"id": p.id, "tool": p.tool, "level": p.level, "cost_eur": str(p.cost_eur),
                         "origin": p.origin, "args": p.args, "args_hash": p.args_hash,
                         "hash_ok": p.hash_ok} for p in items])

    @app.get("/api/audit")
    @guarded
    def audit_list():
        rows = conn().execute("select seq, ts_utc, type, db_role from ape.audit_event "
                              "order by seq desc limit 40").fetchall()
        return jsonify([{"seq": s, "at": t, "type": ty, "role": r} for s, t, ty, r in rows])

    # ------------------------------------------------------------------ acciones de Dani
    @app.post("/api/say")
    @guarded
    def say():
        text = str(body().get("text", "")).strip()
        if not text or len(text) > 4000:
            return err("el mensaje debe tener entre 1 y 4000 caracteres", 400)
        mid = admin.say(conn(), text)
        audit("panel.say", {"inbox_id": mid})
        return jsonify({"ok": True})

    def stepup(kind: str):
        if fails(kind) >= MAX_FAILS:
            return err("demasiados intentos; espera unos minutos", 429)
        row = auth_row()
        if row is None or not use_totp(str(body().get("code", "")), row):
            note(kind, False)
            return err("código incorrecto o ya usado: espera al siguiente de la app", 403)
        note(kind, True)
        return None

    @app.post("/api/approve")
    @guarded
    def approve():
        bad = stepup("stepup")
        if bad:
            return bad
        action_id = str(body().get("id", ""))
        try:
            ap = admin.approve(conn(), action_id, cfg.approval_secret, hours=24)
        except admin.AdminError as exc:
            return err(str(exc), 409)
        audit("panel.approve", {"id": action_id, "expires_at": ap.expires_at.isoformat()})
        return jsonify({"ok": True, "expires_at": ap.expires_at.isoformat()})

    @app.post("/api/reject")
    @guarded
    def reject():
        action_id = str(body().get("id", ""))
        try:
            admin.reject(conn(), action_id)
        except admin.AdminError as exc:
            return err(str(exc), 409)
        audit("panel.reject", {"id": action_id})
        return jsonify({"ok": True})

    @app.post("/api/kill")
    @guarded
    def kill():
        admin.kill(conn(), str(body().get("reason", ""))[:200] or "desde el panel")
        audit("panel.kill", {})
        return jsonify({"ok": True})

    @app.post("/api/resume")
    @guarded
    def resume():
        bad = stepup("stepup")
        if bad:
            return bad
        admin.resume(conn())
        audit("panel.resume", {})
        return jsonify({"ok": True})

    @app.post("/api/run-cycle")
    @guarded
    def run_cycle():
        if not (cfg.github_token and cfg.github_repo):
            return err("no configurado", 501)
        url = f"{cfg.github_api.rstrip('/')}/repos/{cfg.github_repo}/actions/workflows/{cfg.github_workflow}/dispatches"
        req = urllib.request.Request(url, data=json.dumps({"ref": "main"}).encode(), method="POST", headers={
            "Authorization": "Bearer " + cfg.github_token, "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json",
            "User-Agent": "ape-panel"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                ok = resp.status == 204
        except (urllib.error.URLError, TimeoutError):
            ok = False
        if not ok:
            return err("no se pudo lanzar el ciclo", 502)
        audit("panel.run_cycle", {})
        return jsonify({"ok": True})

    return app
