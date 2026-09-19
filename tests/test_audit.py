import dataclasses

from hypothesis import given, settings, strategies as st

from ape.audit import GENESIS, AuditRow, compute_hash, event_canon, head, verify_chain, verify_head


def build(n, role="ape_agent"):
    rows, prev = [], GENESIS
    for i in range(1, n + 1):
        canon = event_canon("agente", "evento", {"i": i})
        ts = f"2026-09-18T12:00:{i:02d}.000000Z"
        h = compute_hash(prev, ts, role, canon)
        rows.append(AuditRow(i, ts, role, canon, prev, h))
        prev = h
    return rows


def test_cadena_integra_y_vacia():
    assert verify_chain([]) is None
    assert verify_chain(build(20)) is None


def test_modificar_contenido_se_detecta():
    rows = build(10)
    rows[4] = dataclasses.replace(rows[4], canon=event_canon("agente", "evento", {"i": 999}))
    assert verify_chain(rows) == 5


def test_modificar_rol_o_fecha_se_detecta():
    rows = build(6)
    rows[2] = dataclasses.replace(rows[2], db_role="postgres")
    assert verify_chain(rows) == 3
    rows = build(6)
    rows[1] = dataclasses.replace(rows[1], ts_utc="2020-01-01T00:00:00.000000Z")
    assert verify_chain(rows) == 2


def test_borrar_un_evento_intermedio_se_detecta():
    rows = build(10)
    del rows[4]
    assert verify_chain(rows) == 6


def test_reordenar_no_oculta_nada():
    rows = build(8)
    rows[2], rows[3] = rows[3], rows[2]
    assert verify_chain(rows) is None  # se reordena por seq; el contenido sigue íntegro


def test_borrar_el_primero_se_detecta():
    rows = build(5)[1:]
    assert verify_chain(rows) == 2


def test_recortar_el_final_no_se_detecta_pero_cambia_la_cabeza():
    rows = build(10)
    assert verify_chain(rows[:-1]) is None
    assert head(rows[:-1]) != head(rows)  # por eso la cabeza se ancla fuera de la BD


def test_cabeza_anclada_detecta_recorte_y_manipulacion():
    rows = build(10)
    anchored = head(rows)
    assert verify_head(rows, anchored) is True
    assert verify_head(rows[:-1], anchored) is False
    altered = dataclasses.replace(rows[4], canon=event_canon("agente", "evento", {"i": 999}))
    assert verify_head([*rows[:4], altered, *rows[5:]], anchored) is False


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=2, max_value=30), st.data())
def test_propiedad_cualquier_alteracion_se_detecta(n, data):
    rows = build(n)
    i = data.draw(st.integers(0, n - 1))
    field = data.draw(st.sampled_from(["canon", "ts_utc", "db_role", "prev_hash", "hash"]))
    original = getattr(rows[i], field)
    rows[i] = dataclasses.replace(rows[i], **{field: original + "x"})
    assert verify_chain(rows) is not None
