"""Motor de políticas: determinista, sin LLM.

El LLM PROPONE una acción; este motor DECIDE; otra pieza EJECUTA.
El nivel de una acción y si implica dinero salen del REGISTRO de herramientas,
nunca de lo que declare quien la propone.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum, IntEnum
from hashlib import sha256
from typing import Any, Mapping, Optional

from .canon import args_hash as compute_args_hash
from .canon import iso_utc, money


class Level(IntEnum):
    N0 = 0  # leer, analizar, redactar
    N1 = 1  # interno, reversible, gratuito
    N2 = 2  # externo sin dinero
    N3 = 3  # dinero o irreversible con aprobación de Dani


class Origin(str, Enum):
    DANI = "dani"
    AGENT = "agent"
    EXTERNAL = "external_content"  # inyección indirecta posible: contenido no confiable


class Code(str, Enum):
    ALLOWED = "allowed"
    KILL_SWITCH = "kill_switch"
    UNKNOWN_TOOL = "unknown_tool"
    DUPLICATE = "duplicate_idempotency_key"
    INVALID_COST = "invalid_cost"
    NEEDS_APPROVAL = "needs_approval"
    BAD_APPROVAL = "bad_approval"
    RATE_LIMIT = "rate_limit"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    level: Level
    involves_money: bool = False
    reversible: bool = True
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.involves_money and self.level != Level.N3:
            raise ValueError("una herramienta con dinero debe ser N3")


@dataclass(frozen=True)
class ActionRequest:
    id: str
    tool: str
    args: Mapping[str, Any]
    origin: Origin
    idempotency_key: str
    cost_eur: Decimal = Decimal("0")


@dataclass(frozen=True)
class Approval:
    action_id: str
    args_hash: str
    approver: str
    amount_eur: Decimal
    expires_at: datetime
    signature: str


@dataclass(frozen=True)
class PolicyState:
    kill_active: bool = False
    approver: str = "dani"
    max_n2_per_hour: int = 20
    recent_counts: Mapping[str, int] = field(default_factory=dict)  # por herramienta, última hora
    seen_idempotency_keys: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: Code
    reason: str
    level: Optional[Level] = None
    involves_money: bool = False
    tainted: bool = False  # acción N2+ derivada de contenido externo: se registra con su origen


class ToolRegistry:
    def __init__(self, specs: list[ToolSpec]):
        self._specs = {s.name: s for s in specs}

    def get(self, name: str) -> Optional[ToolSpec]:
        spec = self._specs.get(name)
        return spec if spec and spec.enabled else None


# --- Aprobaciones firmadas -------------------------------------------------
# La clave HMAC NO está en la base de datos ni en el proceso del agente.

def _approval_message(action_id: str, ahash: str, approver: str,
                      amount: Decimal, expires_at: datetime) -> bytes:
    return "|".join([action_id, ahash, approver, money(amount), iso_utc(expires_at)]).encode()


def sign_approval(secret: bytes, action_id: str, ahash: str, approver: str,
                  amount: Decimal, expires_at: datetime) -> str:
    return hmac.new(secret, _approval_message(action_id, ahash, approver, amount, expires_at),
                    sha256).hexdigest()


def _approval_problem(req: ActionRequest, ahash: str, approval: Approval,
                      state: PolicyState, secret: bytes, now: datetime) -> Optional[str]:
    if approval.action_id != req.id:
        return "la aprobación es de otra acción"
    if approval.args_hash != ahash:
        return "los argumentos han cambiado desde la aprobación"
    if approval.approver != state.approver:
        return "aprobador no autorizado"
    if approval.expires_at <= now:
        return "aprobación caducada"
    if approval.amount_eur < req.cost_eur:
        return "importe aprobado inferior al coste"
    expected = sign_approval(secret, approval.action_id, approval.args_hash,
                             approval.approver, approval.amount_eur, approval.expires_at)
    if not hmac.compare_digest(expected, approval.signature):
        return "firma inválida"
    return None


class PolicyEngine:
    def __init__(self, registry: ToolRegistry, approval_secret: bytes):
        if not approval_secret:
            raise ValueError("se requiere la clave de aprobaciones")
        self._registry = registry
        self._secret = approval_secret

    def evaluate(self, req: ActionRequest, state: PolicyState,
                 approval: Optional[Approval] = None,
                 now: Optional[datetime] = None) -> Decision:
        now = now or datetime.now(timezone.utc)

        # 1. Parada: nada se ejecuta, sin excepciones.
        if state.kill_active:
            return Decision(False, Code.KILL_SWITCH, "parada activa")

        # 2. Herramienta: solo las registradas y habilitadas.
        spec = self._registry.get(req.tool)
        if spec is None:
            return Decision(False, Code.UNKNOWN_TOOL, f"herramienta desconocida o deshabilitada: {req.tool}")

        # 3. Validaciones básicas.
        if req.cost_eur < 0:
            return Decision(False, Code.INVALID_COST, "coste negativo")
        if req.idempotency_key in state.seen_idempotency_keys:
            return Decision(False, Code.DUPLICATE, "clave de idempotencia repetida")

        # 4. El nivel sale del registro. Cualquier coste convierte la acción en N3 con dinero.
        money_involved = spec.involves_money or req.cost_eur > 0
        level = Level.N3 if money_involved else spec.level
        tainted = level >= Level.N2 and req.origin == Origin.EXTERNAL

        # 5. N3 (todo el dinero, contratos, irreversibles): exige aprobación firmada de Dani.
        #    No existe gasto autónomo: la base de datos impone lo mismo.
        if level == Level.N3:
            if approval is None:
                return Decision(False, Code.NEEDS_APPROVAL, "requiere aprobación de Dani",
                                level, money_involved, tainted)
            problem = _approval_problem(req, compute_args_hash(req.args), approval,
                                        state, self._secret, now)
            if problem:
                return Decision(False, Code.BAD_APPROVAL, problem, level, money_involved, tainted)
            return Decision(True, Code.ALLOWED, "aprobada por Dani", level, money_involved, tainted)

        # 6. N2: autonomía total, pero con límite de frecuencia y registro de origen.
        if level == Level.N2:
            if state.recent_counts.get(req.tool, 0) >= state.max_n2_per_hour:
                return Decision(False, Code.RATE_LIMIT, "límite de frecuencia alcanzado",
                                level, False, tainted)

        return Decision(True, Code.ALLOWED, "permitida", level, False, tainted)
