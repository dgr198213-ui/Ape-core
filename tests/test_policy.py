from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from hypothesis import given, settings, strategies as st

from ape.canon import args_hash
from ape.policy import (ActionRequest, Approval, Code, Level, Origin, PolicyEngine,
                        PolicyState, ToolRegistry, ToolSpec, sign_approval)

SECRET = b"clave-de-pruebas-que-el-agente-no-tiene"
NOW = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)

REGISTRY = ToolRegistry([
    ToolSpec("memory.search", Level.N0),
    ToolSpec("memory.write", Level.N1),
    ToolSpec("message.send", Level.N2, reversible=False),
    ToolSpec("contract.sign", Level.N3, reversible=False),
    ToolSpec("payment.execute", Level.N3, involves_money=True, reversible=False),
    ToolSpec("old.tool", Level.N0, enabled=False),
])
ENGINE = PolicyEngine(REGISTRY, SECRET)
TOOLS = ["memory.search", "memory.write", "message.send", "contract.sign",
         "payment.execute", "old.tool", "nope"]


def req(tool="memory.search", cost="0", origin=Origin.AGENT, key="k1", args=None, id_="a1"):
    return ActionRequest(id=id_, tool=tool, args=args or {"x": 1}, origin=origin,
                         idempotency_key=key, cost_eur=Decimal(cost))


def approval_for(r, amount=None, approver="dani", expires=None, secret=SECRET, ahash=None):
    amount = Decimal(amount) if amount is not None else r.cost_eur
    expires = expires or NOW + timedelta(hours=1)
    ahash = ahash or args_hash(r.args)
    return Approval(r.id, ahash, approver, amount, expires,
                    sign_approval(secret, r.id, ahash, approver, amount, expires))


# ---------------- comportamiento básico ----------------

def test_n0_n1_libres():
    assert ENGINE.evaluate(req("memory.search"), PolicyState(), now=NOW).allowed
    assert ENGINE.evaluate(req("memory.write"), PolicyState(), now=NOW).allowed


def test_herramienta_desconocida_o_deshabilitada():
    assert ENGINE.evaluate(req("nope"), PolicyState(), now=NOW).code == Code.UNKNOWN_TOOL
    assert ENGINE.evaluate(req("old.tool"), PolicyState(), now=NOW).code == Code.UNKNOWN_TOOL


def test_dinero_sin_aprobacion_se_bloquea():
    d = ENGINE.evaluate(req("payment.execute", cost="10"), PolicyState(), now=NOW)
    assert not d.allowed and d.code == Code.NEEDS_APPROVAL and d.involves_money


def test_cualquier_coste_convierte_la_accion_en_n3():
    # Una herramienta N0 que pretende costar dinero no puede colarse como gratuita.
    d = ENGINE.evaluate(req("memory.search", cost="0.01"), PolicyState(), now=NOW)
    assert not d.allowed and d.level == Level.N3


def test_dinero_con_aprobacion_valida_se_permite():
    r = req("payment.execute", cost="10")
    d = ENGINE.evaluate(r, PolicyState(), approval_for(r), now=NOW)
    assert d.allowed and d.code == Code.ALLOWED


def test_contrato_sin_dinero_tambien_exige_aprobacion():
    assert ENGINE.evaluate(req("contract.sign"), PolicyState(), now=NOW).code == Code.NEEDS_APPROVAL


def test_n2_libre_pero_marca_origen_externo():
    d = ENGINE.evaluate(req("message.send", origin=Origin.EXTERNAL), PolicyState(), now=NOW)
    assert d.allowed and d.tainted
    d2 = ENGINE.evaluate(req("message.send", origin=Origin.DANI), PolicyState(), now=NOW)
    assert d2.allowed and not d2.tainted


def test_limite_de_frecuencia_n2():
    st_ = PolicyState(max_n2_per_hour=3, recent_counts={"message.send": 3})
    assert ENGINE.evaluate(req("message.send"), st_, now=NOW).code == Code.RATE_LIMIT


def test_idempotencia():
    st_ = PolicyState(seen_idempotency_keys=frozenset({"k1"}))
    assert ENGINE.evaluate(req("memory.search", key="k1"), st_, now=NOW).code == Code.DUPLICATE


def test_coste_negativo():
    assert ENGINE.evaluate(req("payment.execute", cost="-5"), PolicyState(), now=NOW).code == Code.INVALID_COST


def test_registro_rechaza_herramienta_de_dinero_que_no_sea_n3():
    with pytest.raises(ValueError):
        ToolSpec("x", Level.N1, involves_money=True)


# ---------------- la aprobación no se puede manipular ----------------

def test_aprobacion_ligada_a_los_argumentos():
    r = req("payment.execute", cost="10", args={"to": "A", "amount": 10})
    ap = approval_for(r)
    r2 = req("payment.execute", cost="10", args={"to": "MALICIOSO", "amount": 10})
    d = ENGINE.evaluate(r2, PolicyState(), ap, now=NOW)
    assert not d.allowed and d.code == Code.BAD_APPROVAL


def test_aprobacion_de_otra_accion():
    r = req("payment.execute", cost="10", id_="a1")
    other = req("payment.execute", cost="10", id_="a2")
    assert not ENGINE.evaluate(r, PolicyState(), approval_for(other), now=NOW).allowed


@pytest.mark.parametrize("mutate", ["caducada", "importe_bajo", "otro_aprobador",
                                    "firma_falsa", "clave_distinta"])
def test_aprobaciones_invalidas(mutate):
    r = req("payment.execute", cost="10")
    if mutate == "caducada":
        ap = approval_for(r, expires=NOW - timedelta(seconds=1))
    elif mutate == "importe_bajo":
        ap = approval_for(r, amount="9.99")
    elif mutate == "otro_aprobador":
        ap = approval_for(r, approver="agente")
    elif mutate == "clave_distinta":
        ap = approval_for(r, secret=b"otra-clave")
    else:
        ap = approval_for(r)
        ap = Approval(ap.action_id, ap.args_hash, ap.approver, ap.amount_eur, ap.expires_at, "0" * 64)
    d = ENGINE.evaluate(r, PolicyState(), ap, now=NOW)
    assert not d.allowed and d.code == Code.BAD_APPROVAL


def test_la_clave_no_puede_ser_vacia():
    with pytest.raises(ValueError):
        PolicyEngine(REGISTRY, b"")


def test_motor_sin_clave_clasifica_pero_no_valida_aprobaciones():
    solo_proponer = PolicyEngine(REGISTRY, None)
    r = req("payment.execute", cost="10")
    assert solo_proponer.evaluate(r, PolicyState(), now=NOW).code == Code.NEEDS_APPROVAL
    d = solo_proponer.evaluate(r, PolicyState(), approval_for(r), now=NOW)
    assert not d.allowed and d.code == Code.BAD_APPROVAL
    assert solo_proponer.evaluate(req("memory.search"), PolicyState(), now=NOW).allowed


# ---------------- propiedades ----------------

requests_st = st.builds(
    lambda tool, cost, origin, key, args: ActionRequest(
        id="a1", tool=tool, args=args, origin=origin, idempotency_key=key, cost_eur=Decimal(cost)),
    tool=st.sampled_from(TOOLS),
    cost=st.decimals(min_value=Decimal("-5"), max_value=Decimal("1000"), places=2, allow_nan=False),
    origin=st.sampled_from(list(Origin)),
    key=st.text(min_size=1, max_size=5),
    args=st.dictionaries(st.text(max_size=3), st.integers(), max_size=3),
)
states_st = st.builds(
    PolicyState,
    kill_active=st.booleans(),
    max_n2_per_hour=st.integers(min_value=0, max_value=50),
    recent_counts=st.dictionaries(st.sampled_from(TOOLS), st.integers(0, 60)),
)


@settings(max_examples=400, deadline=None)
@given(requests_st, states_st)
def test_propiedad_sin_aprobacion_nunca_hay_dinero_ni_n3(r, state):
    d = ENGINE.evaluate(r, state, approval=None, now=NOW)
    if d.allowed:
        assert not d.involves_money
        assert d.level != Level.N3
        assert r.cost_eur == 0


@settings(max_examples=400, deadline=None)
@given(requests_st)
def test_propiedad_parada_bloquea_todo(r):
    ap = approval_for(r) if r.cost_eur >= 0 else None
    d = ENGINE.evaluate(r, PolicyState(kill_active=True), ap, now=NOW)
    assert not d.allowed and d.code == Code.KILL_SWITCH


@settings(max_examples=300, deadline=None)
@given(requests_st, st.decimals(min_value=Decimal("0"), max_value=Decimal("1000"), places=2, allow_nan=False))
def test_propiedad_aprobacion_por_debajo_del_coste_nunca_vale(r, amount):
    if r.cost_eur <= amount:
        return
    d = ENGINE.evaluate(r, PolicyState(), approval_for(r, amount=amount), now=NOW)
    assert not d.allowed


@settings(max_examples=300, deadline=None)
@given(requests_st, st.dictionaries(st.text(max_size=3), st.integers(), max_size=3))
def test_propiedad_cambiar_args_invalida_la_aprobacion(r, other_args):
    if r.cost_eur < 0 or args_hash(other_args) == args_hash(r.args):
        return
    ap = approval_for(r)
    changed = ActionRequest(r.id, r.tool, other_args, r.origin, r.idempotency_key, r.cost_eur)
    d = ENGINE.evaluate(changed, PolicyState(), ap, now=NOW)
    if d.level == Level.N3:
        assert not d.allowed


def test_secret_bytes():
    from ape.canon import secret_bytes
    assert secret_bytes("aa" * 32) == bytes.fromhex("aa" * 32)                 # hexadecimal: se decodifica
    assert secret_bytes("Zk3-p9Q_una cadena larga de un gestor 8842") == "Zk3-p9Q_una cadena larga de un gestor 8842".encode()
    assert secret_bytes("  " + "ab" * 16 + "  ") == bytes.fromhex("ab" * 16)      # se recortan espacios
    for bad in ("", "corta", "aa" * 15, None):
        with pytest.raises(ValueError):
            secret_bytes(bad)
