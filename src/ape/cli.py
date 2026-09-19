"""Herramienta de línea de comandos de Dani.

Variables de entorno:
  APE_DSN_ADMIN         conexión del propietario (aprobar, parar, escribir en la bandeja)
  APE_DSN_AGENT         conexión del rol ape_agent (solo para `cycle`)
  APE_APPROVAL_SECRET   clave HMAC de aprobaciones, en hexadecimal (solo para `approve`)
  APE_CONFIG            ruta al JSON de configuración (endpoints de modelos, Telegram)
"""
from __future__ import annotations

import argparse
import os
import sys

from . import admin
from .config import ConfigError, load_config, load_notifier, load_router
from .cycle import Cycle


def _conn(var: str):
    import psycopg
    dsn = os.environ.get(var)
    if not dsn:
        raise SystemExit(f"Falta {var}")
    return psycopg.connect(dsn, autocommit=True)


def _secret() -> bytes:
    raw = os.environ.get("APE_APPROVAL_SECRET", "")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise SystemExit("APE_APPROVAL_SECRET debe ser hexadecimal") from None
    if len(key) < 16:
        raise SystemExit("APE_APPROVAL_SECRET demasiado corta (mínimo 16 bytes)")
    return key


def cmd_say(a):
    print("recibido:", admin.say(_conn("APE_DSN_ADMIN"), " ".join(a.text)))


def cmd_pending(a):
    items = admin.pending(_conn("APE_DSN_ADMIN"))
    if not items:
        print("Nada pendiente.")
    for p in items:
        flag = "" if p.hash_ok else "  ⚠ HASH NO COINCIDE CON LOS ARGUMENTOS"
        print(f"{p.id}  {p.tool}  N{p.level}  {p.cost_eur} €  origen={p.origin}{flag}")
        print(f"    args: {p.args}")


def cmd_approve(a):
    conn = _conn("APE_DSN_ADMIN")
    act = next((p for p in admin.pending(conn) if p.id == a.action_id), None)
    if act is None:
        raise SystemExit("No existe esa acción pendiente.")
    print(f"{act.tool}  N{act.level}  {act.cost_eur} €  origen={act.origin}\nargs: {act.args}")
    if act.origin == "external_content":
        print("⚠ Derivada de contenido externo (posible inyección). Revísala con especial cuidado.")
    confirm = a.confirm_id or input(f"Escribe los 8 primeros caracteres del id ({act.id[:8]}) para aprobar: ")
    if confirm.strip() != act.id[:8]:
        raise SystemExit("Confirmación incorrecta. No se aprueba nada.")
    ap = admin.approve(conn, act.id, _secret(), hours=a.hours)
    print(f"Aprobada hasta {ap.expires_at.isoformat()}")


def cmd_reject(a):
    admin.reject(_conn("APE_DSN_ADMIN"), a.action_id)
    print("Rechazada.")


def cmd_kill(a):
    admin.kill(_conn("APE_DSN_ADMIN"), " ".join(a.reason))
    print("PARADA ACTIVADA. Ningún ciclo actuará hasta `ape resume`.")


def cmd_resume(a):
    admin.resume(_conn("APE_DSN_ADMIN"))
    print("Reanudado.")


def cmd_verify(a):
    bad = admin.audit_verify(_conn("APE_DSN_ADMIN"))
    print("Cadena de auditoría íntegra." if bad is None else f"CADENA ROTA en seq={bad}")
    raise SystemExit(0 if bad is None else 1)


def cmd_cycle(a):
    try:
        cfg = load_config(os.environ.get("APE_CONFIG"))
        router, notifier = load_router(cfg), load_notifier(cfg)
    except ConfigError as exc:
        raise SystemExit(f"Configuración: {exc}") from None
    rep = Cycle(_conn("APE_DSN_AGENT"), router, notifier).run()
    print(rep)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="ape")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("say", help="deja un mensaje en la bandeja del agente"); s.add_argument("text", nargs="+"); s.set_defaults(f=cmd_say)
    sub.add_parser("pending", help="acciones N3 pendientes de tu aprobación").set_defaults(f=cmd_pending)
    s = sub.add_parser("approve"); s.add_argument("action_id"); s.add_argument("--hours", type=int, default=24)
    s.add_argument("--confirm-id"); s.set_defaults(f=cmd_approve)
    s = sub.add_parser("reject"); s.add_argument("action_id"); s.set_defaults(f=cmd_reject)
    s = sub.add_parser("kill", help="PARADA inmediata"); s.add_argument("reason", nargs="*"); s.set_defaults(f=cmd_kill)
    sub.add_parser("resume").set_defaults(f=cmd_resume)
    sub.add_parser("audit-verify").set_defaults(f=cmd_verify)
    sub.add_parser("cycle", help="ejecuta un ciclo (solo propone)").set_defaults(f=cmd_cycle)
    a = ap.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main(sys.argv[1:])
