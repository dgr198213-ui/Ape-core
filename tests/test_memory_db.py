import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg import errors as E  # noqa: E402

from helpers import as_agent  # noqa: E402


def sens(db, source, wanted=0, who="ape_agent"):
    db.execute(f"set session authorization {who}")
    try:
        return db.execute(
            "insert into ape.memory(kind, content, source, sensitivity) values "
            "('semantica', 'c', %s, %s) returning sensitivity", (source, wanted)).fetchone()[0]
    finally:
        db.execute("reset session authorization")


# ---------------- la política fija la sensibilidad mínima por origen ----------------

@pytest.mark.parametrize("source,wanted,expected", [
    ("gmail", 0, 2), ("finance", 0, 2), ("health", 1, 2),        # origen sensible: no se puede rebajar
    ("manual_dani", 0, 1), ("calendar", 0, 1),
    ("web_public", 0, 0),                                          # público: se respeta
    ("origen_nuevo", 0, 2),                                        # desconocido: falla cerrado
    ("web_public", 2, 2),                                          # subirla siempre se permite
])
def test_sensibilidad_minima_por_origen(pgdb, source, wanted, expected):
    assert sens(pgdb, source, wanted) == expected


def test_el_agente_no_puede_reclasificar_ni_reescribir_recuerdos(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    mid = agent.execute("insert into ape.memory(kind, content, source) values "
                        "('semantica','dato','gmail') returning id").fetchone()[0]
    for stmt in ("update ape.memory set sensitivity = 0 where id = %s",
                 "update ape.memory set content = 'x' where id = %s",
                 "update ape.memory set source = 'web_public' where id = %s",
                 "update ape.memory set pinned = true where id = %s",
                 "delete from ape.memory where id = %s"):
        with pytest.raises(E.InsufficientPrivilege):
            agent.execute(stmt, (mid,))
    agent.execute("update ape.memory set salience = 0.9, last_used_at = now() where id = %s", (mid,))
    agent.close()


def test_el_agente_no_puede_fijar_recuerdos_al_insertar(pgdb):
    agent = as_agent(pgdb.conninfo_str)
    p = agent.execute("insert into ape.memory(kind, content, source, pinned) values "
                      "('semantica','x','web_public', true) returning pinned").fetchone()[0]
    assert p is False
    agent.close()


# ---------------- olvido activo ----------------

def fill(db, n, source="web_public"):
    for i in range(n):
        db.execute("insert into ape.memory(kind, content, source, salience) values "
                   "('semantica', %s, %s, %s)", (f"m{i}", source, (i + 1) / (n + 1)))


def test_olvido_conserva_los_mejores_y_respeta_lo_fijado(pgdb):
    pgdb.execute("update ape.core_policy set value = '10'::jsonb where key = 'memory_max_rows'")
    fill(pgdb, 25)
    pgdb.execute("insert into ape.memory(kind, content, source, salience, pinned) values "
                 "('semantica','FIJADO','web_public', 0.0001, true)")
    agent = as_agent(pgdb.conninfo_str)
    deleted = agent.execute("select ape.memory_forget()").fetchone()[0]
    agent.close()
    rows = [r[0] for r in pgdb.execute("select content from ape.memory")]
    assert "FIJADO" in rows                                 # lo fijado nunca se olvida
    assert len(rows) == 9 and deleted == 25 - 8             # 90 % de 10 = 9: 8 normales + el fijado
    kept = sorted(r for r in rows if r != "FIJADO")
    assert kept == sorted(f"m{i}" for i in range(17, 25))   # las 8 de mayor salience
    assert pgdb.execute("select count(*) from ape.audit_event where type = 'memory.forget'").fetchone()[0] == 1
    assert pgdb.execute("select ape.audit_verify()").fetchone()[0] is None


def test_olvido_no_hace_nada_por_debajo_del_maximo(pgdb):
    fill(pgdb, 5)
    agent = as_agent(pgdb.conninfo_str)
    assert agent.execute("select ape.memory_forget()").fetchone()[0] == 0
    agent.close()
    assert pgdb.execute("select count(*) from ape.memory").fetchone()[0] == 5


def test_lo_reciente_y_usado_pesa_mas_que_lo_viejo(pgdb):
    pgdb.execute("update ape.core_policy set value = '2'::jsonb where key = 'memory_max_rows'")
    pgdb.execute("update ape.core_policy set value = '1'::jsonb where key = 'memory_half_life_days'")
    pgdb.execute("insert into ape.memory(kind, content, source, salience, created_at) values "
                 "('semantica','viejo','web_public', 0.9, now() - interval '30 days')")
    pgdb.execute("insert into ape.memory(kind, content, source, salience, created_at, last_used_at) values "
                 "('semantica','usado','web_public', 0.5, now() - interval '30 days', now())")
    pgdb.execute("insert into ape.memory(kind, content, source, salience) values "
                 "('semantica','nuevo','web_public', 0.5)")
    agent = as_agent(pgdb.conninfo_str)
    agent.execute("select ape.memory_forget()")
    agent.close()
    assert "viejo" not in [r[0] for r in pgdb.execute("select content from ape.memory")]


# ---------------- búsqueda vectorial con filtro de clase ----------------

def vec(x):
    return "[" + ",".join([str(x)] + ["0"] * 767) + "]"


def test_busqueda_filtra_por_clase_y_ordena_por_cercania(pgdb):
    for content, source, x in [("publico-cerca", "web_public", 1.0), ("publico-lejos", "web_public", 0.2),
                               ("sensible-cerca", "finance", 1.0)]:
        pgdb.execute("insert into ape.memory(kind, content, source, sensitivity, embedding) values "
                     "('semantica', %s, %s, 0, %s::extensions.vector)",
                     (content, source, f"[{x},{1 - x},0" + ",0" * 765 + "]"))
    agent = as_agent(pgdb.conninfo_str)
    q = "[1,0,0" + ",0" * 765 + "]"
    rows = agent.execute("select content from ape.memory_search(%s::extensions.vector, 0::smallint, 5)", (q,)).fetchall()
    assert [r[0] for r in rows] == ["publico-cerca", "publico-lejos"]      # lo sensible no sale
    rows = agent.execute("select content from ape.memory_search(%s::extensions.vector, 2::smallint, 1)", (q,)).fetchall()
    assert len(rows) == 1
    agent.close()


# ---------------- bandeja de entrada ----------------

def test_bandeja_distingue_a_dani_de_lo_externo(pgdb):
    pgdb.execute("insert into ape.inbox(source, content) values ('manual_dani', 'de Dani')")
    agent = as_agent(pgdb.conninfo_str)
    agent.execute("insert into ape.inbox(source, content, from_dani) values ('web_public','externo', true)")
    rows = dict(pgdb.execute("select content, from_dani from ape.inbox").fetchall())
    assert rows == {"de Dani": True, "externo": False}         # el agente no puede hacerse pasar por Dani
    with pytest.raises(E.InsufficientPrivilege):
        agent.execute("update ape.inbox set content = 'x'")
    with pytest.raises(E.InsufficientPrivilege):
        agent.execute("update ape.inbox set from_dani = true")
    agent.execute("update ape.inbox set processed_at = now()")
    agent.close()
