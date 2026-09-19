import pytest

from ape.classification import DataClass, Endpoint, EndpointKind
from ape.router import LLMEndpoint, LLMError, NoEligibleEndpoint, Router

from helpers import FREE, LOCAL, MockLLM, endpoint


@pytest.fixture
def servers():
    made = []

    def make(**kw):
        m = MockLLM(**kw)
        made.append(m)
        return m
    yield make
    for m in made:
        m.close()


def test_llamada_correcta_y_forma_de_la_peticion(servers):
    m = servers(reply="hola")
    r = Router([endpoint("gemini-free", FREE, m, key="SECRETO-123", model="modelo-x")])
    out = r.complete("sistema", "usuario", DataClass.PUBLIC)
    assert out.text == "hola" and out.endpoint == "gemini-free"
    req = m.requests[0]
    assert req["path"] == "/chat/completions"
    assert req["headers"]["Authorization"] == "Bearer SECRETO-123"
    assert req["body"]["model"] == "modelo-x" and req["body"]["temperature"] == 0
    assert [x["role"] for x in req["body"]["messages"]] == ["system", "user"]


def test_la_clave_no_aparece_en_repr():
    m = MockLLM()
    try:
        ep = endpoint("x", FREE, m, key="SECRETO-123")
        assert "SECRETO-123" not in repr(ep)
    finally:
        m.close()


def test_cascada_si_el_primero_falla(servers):
    caido, bueno = servers(status=500), servers(reply="ok")
    r = Router([endpoint("a", FREE, caido), endpoint("b", FREE, bueno)])
    assert r.complete("s", "u", DataClass.PUBLIC).endpoint == "b"
    assert len(caido.requests) == 1


def test_si_todos_fallan_el_error_no_filtra_claves_ni_contenido(servers):
    a, b = servers(status=500), servers(status=503)
    r = Router([endpoint("a", FREE, a, key="CLAVE-A"), endpoint("b", FREE, b, key="CLAVE-B")])
    with pytest.raises(LLMError) as exc:
        r.complete("s", "CONTENIDO-PRIVADO", DataClass.PUBLIC)
    msg = str(exc.value)
    assert "CLAVE" not in msg and "CONTENIDO-PRIVADO" not in msg


def test_respuesta_malformada_pasa_al_siguiente(servers):
    roto, bueno = servers(reply=None), servers(reply="ok")
    r = Router([endpoint("a", FREE, roto), endpoint("b", FREE, bueno)])
    assert r.complete("s", "u", DataClass.PUBLIC).endpoint == "b"


def test_datos_sensibles_no_se_envian_a_ningun_remoto(servers):
    m = servers()
    r = Router([endpoint("remoto", FREE, m, reviewed=True)])
    with pytest.raises(NoEligibleEndpoint):
        r.complete("s", "u", DataClass.SENSITIVE)
    assert m.requests == []                      # ni una sola petición salió


def test_datos_sensibles_solo_al_local(servers):
    local, remoto = servers(reply="local"), servers(reply="remoto")
    r = Router([endpoint("remoto", FREE, remoto, reviewed=True), endpoint("ollama", LOCAL, local)])
    out = r.complete("s", "u", DataClass.SENSITIVE)
    assert out.endpoint == "ollama" and remoto.requests == []


def test_personales_solo_a_locales_o_revisados(servers):
    sin_revisar, revisado = servers(), servers(reply="ok")
    r = Router([endpoint("libre", FREE, sin_revisar), endpoint("revisado", FREE, revisado, reviewed=True)])
    assert r.complete("s", "u", DataClass.PERSONAL).endpoint == "revisado"
    assert sin_revisar.requests == []


def test_max_class(servers):
    m = servers()
    assert Router([]).max_class() == -1
    assert Router([endpoint("a", FREE, m)]).max_class() == 0
    assert Router([endpoint("a", FREE, m, reviewed=True)]).max_class() == 1
    assert Router([endpoint("a", LOCAL, m)]).max_class() == 2


def test_https_obligatorio_salvo_loopback():
    with pytest.raises(ValueError):
        LLMEndpoint(Endpoint("x", EndpointKind.REMOTE_FREE), "http://ejemplo.com/v1", "m")
    LLMEndpoint(Endpoint("x", EndpointKind.REMOTE_FREE), "https://ejemplo.com/v1", "m")
    LLMEndpoint(Endpoint("x", EndpointKind.LOCAL), "http://localhost:11434/v1", "m")


def test_el_modelo_es_obligatorio():
    with pytest.raises(ValueError):
        LLMEndpoint(Endpoint("x", EndpointKind.LOCAL), "http://localhost:11434/v1", "")
