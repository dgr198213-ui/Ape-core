"""Acceso a la base de datos: estado de políticas, registro de herramientas y auditoría."""
from __future__ import annotations

import uuid
from typing import Any

from .audit import event_canon
from .policy import Level, PolicyState, ToolRegistry, ToolSpec


def load_registry(conn) -> ToolRegistry:
    rows = conn.execute(
        "select name, level, involves_money, reversible, enabled from ape.tool_spec").fetchall()
    return ToolRegistry([ToolSpec(n, Level(lv), bool(m), bool(r), bool(e)) for n, lv, m, r, e in rows])


def load_policy(conn) -> dict[str, Any]:
    return {k: v for k, v in conn.execute("select key, value from ape.core_policy")}


def kill_active(conn) -> bool:
    return bool(conn.execute("select active from ape.kill_switch").fetchone()[0])


def recent_n2_counts(conn) -> dict[str, int]:
    rows = conn.execute(
        "select tool, count(*) from ape.action where level = 2 "
        "and created_at > now() - interval '1 hour' group by tool").fetchall()
    return {t: int(n) for t, n in rows}


def load_state(conn, policy: dict[str, Any] | None = None) -> PolicyState:
    policy = policy or load_policy(conn)
    return PolicyState(
        kill_active=kill_active(conn),
        approver=str(policy.get("approver", "dani")),
        max_n2_per_hour=int(policy.get("max_n2_per_hour", 20)),
        recent_counts=recent_n2_counts(conn),
    )


def audit(conn, run_id: uuid.UUID | None, actor: str, type_: str, payload: Any) -> None:
    conn.execute(
        "insert into ape.audit_event(run_id, actor, type, canon) values (%s, %s, %s, %s)",
        (run_id, actor, type_, event_canon(actor, type_, payload, str(run_id) if run_id else None)))
