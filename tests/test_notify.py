import json

import pytest

from ape.notify import NotifyError, TelegramNotifier

from helpers import MockLLM


def test_telegram_envia_al_chat_correcto():
    m = MockLLM()
    try:
        TelegramNotifier("TOKEN-123", "42", api_base=m.base_url).send("hola")
        req = m.requests[0]
        assert req["path"] == "/botTOKEN-123/sendMessage"
        assert req["body"] == {"chat_id": "42", "text": "hola"}
    finally:
        m.close()


def test_el_error_no_filtra_el_token():
    m = MockLLM(status=500)
    try:
        with pytest.raises(NotifyError) as exc:
            TelegramNotifier("TOKEN-123", "42", api_base=m.base_url).send("hola")
        assert "TOKEN" not in str(exc.value)
    finally:
        m.close()


def test_telegram_exige_https():
    with pytest.raises(ValueError):
        TelegramNotifier("t", "1", api_base="http://api.telegram.org")
