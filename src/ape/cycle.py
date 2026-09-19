"""Ciclo del agente — Fase 1: percibe, recuerda, planifica y PROPONE. No ejecuta nada.

Corre con el rol `ape_agent`, que no tiene la clave de aprobaciones.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Optional, Protocol

from psycopg.types.json import Jsonb

from .canon import args_hash, sha256_hex
from .classification import DataClass, combined_class
from .db import audit, kill_active, load_policy, load_registry, load_state
from .notify import Notifier, NotifyError
from .planner import ContextItem, PlanParseError, Proposal, build_prompt, parse_proposals
from .policy import ActionRequest, Code, Level, Origin, PolicyEngine
from .router import LLMError, NoEligibleEndpoint, Router

ACTOR = "cycle"


@dataclass(frozen=True)
class Event:
    id: str
    source: str
    content: str
    external: bool


class Embedder(Protocol):
    def embed(self, text: str) -> list[float]: ...


class InboxPerceiver:
    """Lee la bandeja de entrada. Lo que escribe Dani es de confianza; el resto es externo."""

    def __init__(self, limit: int = 20):
        self._limit = limit

    def poll(self, conn) -> list[Event]:
        rows = conn.execute(
            "select id, source, content, from_dani from ape.inbox "
            "where processed_at is null order by created_at limit %s", (self._limit,)).fetchall()
        return [Event(str(i), s, c, not d) for i, s, c, d in rows]

    def mark_done(self, conn, ids: list[str]) -> None:
        if ids:
            conn.execute("update ape.inbox set processed_at = now() where id = any(%s::uuid[])", (ids,))


@dataclass(frozen=True)
class CycleConfig:
    max_llm_calls: int = 1
    max_context_items: int = 12
    max_proposals: int = 5
    recall_k: int = 6


@dataclass
class CycleReport:
    run_id: str
    skipped: Optional[str] = None
    events: int = 0
    memories_written: int = 0
    withheld: int = 0
    llm_calls: int = 0
    proposals: int = 0
    denied: int = 0
    pending_approval: list[tuple[str, str]] = field(default_factory=list)
    forgotten: int = 0
    errors: list[str] = field(default_factory=list)


class Cycle:
    def __init__(self, conn, router: Router, notifier: Notifier,
                 perceiver: Optional[InboxPerceiver] = None,
                 embedder: Optional[Embedder] = None,
                 config: CycleConfig = CycleConfig()):
        self._conn = conn
        self._router = router
        self._notifier = notifier
        self._perceiver = perceiver or InboxPerceiver()
        self._embedder = embedder
        self._cfg = config

    # ------------------------------------------------------------------
    def run(self) -> CycleReport:
        conn = self._conn
        run_id = uuid.uuid4()
        rep = CycleReport(run_id=str(run_id))
        audit(conn, run_id, ACTOR, "cycle.start", {"mode": "propose_only"})

        if kill_active(conn):
            rep.skipped = "kill_switch"
            audit(conn, run_id, ACTOR, "cycle.skipped", {"reason": "kill_switch"})
            return rep

        policy = load_policy(conn)
        events = self._perceiver.poll(conn)
        rep.events = len(events)
        stored = self._store_events(events, run_id, rep)
        self._perceiver.mark_done(conn, [e.id for e in events])
        audit(conn, run_id, ACTOR, "cycle.perceived", {"events": [e.id for e in events]})

        cap = self._router.max_class()
        items, withheld = self._build_context(stored, cap, policy)
        rep.withheld = withheld
        if withheld:
            audit(conn, run_id, ACTOR, "context.withheld", {"count": withheld, "endpoint_cap": cap})

        proposals: list[Proposal] = []
        if items and rep.llm_calls < self._cfg.max_llm_calls:
            proposals = self._plan(items, run_id, rep)

        if proposals:
            self._propose(proposals, items, run_id, rep)

        try:
            rep.forgotten = int(conn.execute("select ape.memory_forget()").fetchone()[0])
        except Exception as exc:  # el olvido no debe tumbar el ciclo
            rep.errors.append("forget:" + type(exc).__name__)

        self._notify(rep, run_id)
        audit(conn, run_id, ACTOR, "cycle.end", {
            "events": rep.events, "proposals": rep.proposals, "denied": rep.denied,
            "withheld": rep.withheld, "llm_calls": rep.llm_calls, "forgotten": rep.forgotten,
            "errors": rep.errors})
        return rep

    # ------------------------------------------------------------------
    def _store_events(self, events: list[Event], run_id: uuid.UUID,
                      rep: CycleReport) -> list[tuple[Event, int]]:
        out = []
        for e in events:
            sens = self._conn.execute(
                "insert into ape.memory(kind, content, source, sensitivity, external, salience) "
                "values ('episodica', %s, %s, 0, %s, 0.5) returning sensitivity",
                (e.content, e.source, e.external)).fetchone()[0]
            rep.memories_written += 1
            out.append((e, int(sens)))
        return out

    def _recall(self, cap: int, policy: dict[str, Any], query: str) -> list[ContextItem]:
        if cap < 0:
            return []
        half = float(policy.get("memory_half_life_days", 30))
        rows = None
        if self._embedder is not None and query:
            try:
                vec = "[" + ",".join(f"{x:.6f}" for x in self._embedder.embed(query)) + "]"
                rows = self._conn.execute(
                    "select id, content, sensitivity, external, kind from ape.memory_search("
                    "%s::extensions.vector, %s::smallint, %s)", (vec, cap, self._cfg.recall_k)).fetchall()
                rows = [(i, c, s, x, k) for i, c, s, x, k in rows]
            except Exception:
                rows = None
        if rows is None:
            rows = self._conn.execute(
                "select id, content, sensitivity, external, kind from ape.memory "
                "where sensitivity <= %s order by "
                "ape.memory_score(salience, created_at, last_used_at, %s::real) desc limit %s",
                (cap, half, self._cfg.recall_k)).fetchall()
        return [ContextItem("memory", k, c, int(s), bool(x)) for _, c, s, x, k in rows]

    def _build_context(self, stored: list[tuple[Event, int]], cap: int,
                       policy: dict[str, Any]) -> tuple[list[ContextItem], int]:
        withheld = 0
        items: list[ContextItem] = []
        fresh_texts = []
        for e, sens in stored:
            if sens <= cap:
                items.append(ContextItem("event", e.source, e.content, sens, e.external))
                fresh_texts.append(e.content)
            else:
                withheld += 1
        if items:  # sin eventos utilizables no se planifica: el recuerdo solo acompaña
            seen = {i.content for i in items}
            for m in self._recall(cap, policy, " ".join(fresh_texts)[:2000]):
                if m.content not in seen and len(items) < self._cfg.max_context_items:
                    items.append(m)
                    seen.add(m.content)
        return items[: self._cfg.max_context_items], withheld

    def _plan(self, items: list[ContextItem], run_id: uuid.UUID, rep: CycleReport) -> list[Proposal]:
        registry = load_registry(self._conn)
        tools = sorted((s.name, int(s.level)) for s in
                       (registry.get(n) for n in self._tool_names()) if s is not None)
        goals = [r[0] for r in self._conn.execute(
            "select name from ape.goal where active order by name")]
        system, user = build_prompt(goals, items, tools)
        data_class = combined_class(i.sensitivity for i in items)
        try:
            rep.llm_calls += 1
            done = self._router.complete(system, user, data_class)
        except NoEligibleEndpoint:
            rep.llm_calls -= 1
            rep.errors.append("sin_endpoint_elegible")
            audit(self._conn, run_id, ACTOR, "plan.skipped",
                  {"reason": "no_eligible_endpoint", "class": int(data_class)})
            return []
        except LLMError as exc:
            rep.errors.append("llm_error")
            audit(self._conn, run_id, ACTOR, "plan.failed", {"error": str(exc)})
            return []
        audit(self._conn, run_id, ACTOR, "plan.requested",
              {"endpoint": done.endpoint, "items": len(items), "class": int(data_class)})
        try:
            proposals = parse_proposals(done.text, self._cfg.max_proposals)
        except PlanParseError as exc:
            rep.errors.append("plan_invalid")
            audit(self._conn, run_id, ACTOR, "plan.invalid", {"error": str(exc)})
            return []
        audit(self._conn, run_id, ACTOR, "plan.parsed", {"proposals": len(proposals)})
        return proposals

    def _tool_names(self) -> list[str]:
        return [r[0] for r in self._conn.execute("select name from ape.tool_spec where enabled")]

    def _propose(self, proposals: list[Proposal], items: list[ContextItem],
                 run_id: uuid.UUID, rep: CycleReport) -> None:
        conn = self._conn
        registry = load_registry(conn)
        engine = PolicyEngine(registry, None)          # el agente no tiene la clave
        state = load_state(conn)
        counts = dict(state.recent_counts)
        # Contaminación conservadora: si algo del contexto es externo, la propuesta lo es.
        origin = Origin.EXTERNAL if any(i.external for i in items) else Origin.AGENT

        for p in proposals:
            ahash = args_hash(p.args)
            action_id = uuid.uuid4()
            req = ActionRequest(str(action_id), p.tool, p.args, origin,
                                sha256_hex(f"{p.tool}|{ahash}|{run_id}")[:32], p.cost_eur)
            decision = engine.evaluate(req, replace(state, recent_counts=counts))
            if decision.code not in (Code.ALLOWED, Code.NEEDS_APPROVAL):
                rep.denied += 1
                audit(conn, run_id, ACTOR, "action.denied",
                      {"tool": p.tool, "code": decision.code.value, "args_hash": ahash})
                continue
            dup = conn.execute("select 1 from ape.action where tool = %s and args_hash = %s "
                               "and status = 'propuesta'", (p.tool, ahash)).fetchone()
            if dup:
                audit(conn, run_id, ACTOR, "action.duplicate_pending", {"tool": p.tool, "args_hash": ahash})
                continue
            row = conn.execute(
                "insert into ape.action(id, tool, args, args_hash, cost_eur, origin, idempotency_key) "
                "values (%s, %s, %s, %s, %s, %s, %s) on conflict (idempotency_key) do nothing "
                "returning level", (action_id, p.tool, Jsonb(p.args), ahash, p.cost_eur,
                                    origin.value, req.idempotency_key)).fetchone()
            if row is None:
                continue
            level = Level(row[0])
            rep.proposals += 1
            if level == Level.N2:
                counts[p.tool] = counts.get(p.tool, 0) + 1
            if level == Level.N3:
                rep.pending_approval.append((str(action_id), p.tool))
            audit(conn, run_id, ACTOR, "action.proposed", {
                "id": str(action_id), "tool": p.tool, "level": int(level), "args_hash": ahash,
                "needs_approval": level == Level.N3, "tainted": decision.tainted})

    def _notify(self, rep: CycleReport, run_id: uuid.UUID) -> None:
        if not (rep.events or rep.proposals or rep.withheld or rep.errors):
            return
        lines = [f"Ciclo {rep.run_id[:8]}: {rep.events} entradas, {rep.proposals} propuestas."]
        if rep.pending_approval:
            lines.append(f"{len(rep.pending_approval)} esperan tu aprobación (ape pending).")
        if rep.withheld:
            lines.append(f"{rep.withheld} entradas sensibles no se procesaron: no hay modelo autorizado.")
        if rep.errors:
            lines.append("Incidencias: " + ", ".join(rep.errors))
        try:
            self._notifier.send("\n".join(lines))
        except NotifyError as exc:
            rep.errors.append("notify_failed")
            audit(self._conn, run_id, ACTOR, "notify.failed", {"error": str(exc)})
