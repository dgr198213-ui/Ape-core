"""Operaciones de Dani (rol propietario). Aquí se aprueba, se rechaza y se para el sistema.

Esta capa usa la clave de aprobaciones y la conexión de administrador: no debe ejecutarse en
el mismo proceso ni con las mismas credenciales que el ciclo del agente.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Optional

from .canon import args_hash as compute_args_hash
from .policy import Approval, sign_approval


class AdminError(RuntimeError):
    pass


@dataclass(frozen=True)
class PendingAction:
    id: str
    tool: str
    level: int
    cost_eur: Decimal
    origin: str
    args: dict[str, Any]
    args_hash: str
    hash_ok: bool


def say(conn, text: str, source: str = "manual_dani") -> str:
    if not text.strip():
        raise AdminError("mensaje vacío")
    return str(conn.execute("insert into ape.inbox(source, content) values (%s, %s) returning id",
                            (source, text)).fetchone()[0])


def pending(conn) -> list[PendingAction]:
    rows = conn.execute(
        "select id, tool, level, cost_eur, origin, args, args_hash from ape.action "
        "where status = 'propuesta' and level = 3 order by created_at").fetchall()
    return [PendingAction(str(i), t, lv, c, o, a, h, compute_args_hash(a) == h)
            for i, t, lv, c, o, a, h in rows]


def _load(conn, action_id: str) -> PendingAction:
    for p in pending(conn):
        if p.id == action_id:
            return p
    raise AdminError("la acción no existe, no es N3 o ya no está pendiente")


def approve(conn, action_id: str, secret: bytes, hours: int = 24,
            approver: str = "dani") -> Approval:
    if not secret:
        raise AdminError("falta la clave de aprobaciones")
    if not 1 <= hours <= 24 * 7:
        raise AdminError("la caducidad debe estar entre 1 hora y 7 días")
    act = _load(conn, action_id)
    if not act.hash_ok:
        # El agente guardó un hash que no corresponde a los argumentos: no se firma.
        raise AdminError("el hash de la acción no coincide con sus argumentos; no se aprueba")
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    sig = sign_approval(secret, act.id, act.args_hash, approver, act.cost_eur, expires)
    conn.execute(
        "insert into ape.approval(action_id, args_hash, approver, amount_eur, expires_at, signature) "
        "values (%s, %s, %s, %s, %s, %s)", (act.id, act.args_hash, approver, act.cost_eur, expires, sig))
    conn.execute("update ape.action set status = 'aprobada' where id = %s", (act.id,))
    return Approval(act.id, act.args_hash, approver, act.cost_eur, expires, sig)


def reject(conn, action_id: str) -> None:
    act = _load(conn, action_id)
    conn.execute("update ape.action set status = 'rechazada' where id = %s", (act.id,))


def kill(conn, reason: str) -> None:
    conn.execute("select ape.kill(%s)", (reason or "sin motivo",))


def resume(conn) -> None:
    conn.execute("select ape.resume()")


def audit_verify(conn) -> Optional[int]:
    v = conn.execute("select ape.audit_verify()").fetchone()[0]
    return int(v) if v is not None else None
