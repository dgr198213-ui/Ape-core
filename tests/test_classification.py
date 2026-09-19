from hypothesis import given, strategies as st

from ape.classification import (DataClass, Endpoint, EndpointKind, combined_class, eligible,
                                normalize)

LOCAL = Endpoint("ollama", EndpointKind.LOCAL)
FREE = Endpoint("gemini-free", EndpointKind.REMOTE_FREE)
FREE_OK = Endpoint("zai-free", EndpointKind.REMOTE_FREE, privacy_reviewed=True)
PAID = Endpoint("paid", EndpointKind.REMOTE_PAID, privacy_reviewed=True)
ALL = [LOCAL, FREE, FREE_OK, PAID]


def names(cls):
    return {e.name for e in eligible(cls, ALL)}


def test_publico_a_todos():
    assert names(DataClass.PUBLIC) == {"ollama", "gemini-free", "zai-free", "paid"}


def test_personal_solo_local_o_revisado():
    assert names(DataClass.PERSONAL) == {"ollama", "zai-free", "paid"}


def test_sensible_solo_local():
    assert names(DataClass.SENSITIVE) == {"ollama"}


def test_sensible_sin_local_no_va_a_ningun_lado():
    assert eligible(DataClass.SENSITIVE, [FREE, FREE_OK, PAID]) == []


def test_desconocido_falla_cerrado():
    assert normalize(None) == DataClass.SENSITIVE
    assert normalize(7) == DataClass.SENSITIVE
    assert normalize(-1) == DataClass.SENSITIVE


def test_un_contexto_vale_lo_que_su_fragmento_mas_sensible():
    assert combined_class([0, 0, 2, 1]) == DataClass.SENSITIVE
    assert combined_class([0, None]) == DataClass.SENSITIVE
    assert combined_class([]) == DataClass.PUBLIC


@given(st.lists(st.one_of(st.none(), st.integers(-3, 5)), max_size=8))
def test_propiedad_clase_2_nunca_sale_a_remoto(values):
    cls = combined_class(values)
    if cls == DataClass.SENSITIVE:
        assert all(e.kind == EndpointKind.LOCAL for e in eligible(cls, ALL))
