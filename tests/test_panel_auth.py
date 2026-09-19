import base64

from ape.panel import auth

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


def test_totp_vectores_del_rfc_6238():
    assert auth.hotp(RFC_SECRET, 59 // 30, digits=8) == "94287082"
    assert auth.hotp(RFC_SECRET, 1111111109 // 30, digits=8) == "07081804"
    assert auth.hotp(RFC_SECRET, 1234567890 // 30, digits=8) == "89005924"


def test_ventana_y_un_solo_uso():
    now = 1_800_000_000.0
    step = auth.current_step(now)
    code = auth.hotp(RFC_SECRET, step)
    assert auth.find_totp_step(RFC_SECRET, code, 0, now) == step
    assert auth.find_totp_step(RFC_SECRET, auth.hotp(RFC_SECRET, step - 1), 0, now) == step - 1     # deriva de reloj
    assert auth.find_totp_step(RFC_SECRET, auth.hotp(RFC_SECRET, step + 1), 0, now) == step + 1
    assert auth.find_totp_step(RFC_SECRET, auth.hotp(RFC_SECRET, step + 2), 0, now) is None          # fuera de ventana
    assert auth.find_totp_step(RFC_SECRET, code, step, now) is None                                  # ya usado
    assert auth.find_totp_step(RFC_SECRET, code, step - 1, now) == step


def test_codigos_mal_formados():
    now = 1_800_000_000.0
    for bad in ("", "12345", "1234567", "abcdef", None, "12 34 5"):
        assert auth.find_totp_step(RFC_SECRET, bad, 0, now) is None


def test_frase_de_paso():
    h, salt = auth.hash_passphrase("una frase larga y correcta")
    assert auth.verify_passphrase("una frase larga y correcta", h, salt)
    assert not auth.verify_passphrase("otra frase distinta!!", h, salt)
    h2, salt2 = auth.hash_passphrase("una frase larga y correcta")
    assert salt != salt2 and h != h2


def test_secretos_y_tokens_son_aleatorios_y_se_guardan_hasheados():
    assert auth.new_totp_secret() != auth.new_totp_secret()
    t = auth.new_token()
    assert auth.token_hash(t) != t and len(auth.token_hash(t)) == 64
    assert auth.csrf_for(t) != auth.csrf_for(auth.new_token())
