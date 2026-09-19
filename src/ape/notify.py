"""Canal hacia Dani. Los avisos llevan lo mínimo: nunca contenido ni argumentos."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlparse


class NotifyError(RuntimeError):
    pass


class Notifier(Protocol):
    def send(self, text: str) -> None: ...


class ConsoleNotifier:
    def send(self, text: str) -> None:
        print(text)


@dataclass
class MemoryNotifier:
    """Guarda los mensajes en memoria (pruebas)."""
    messages: list[str] = field(default_factory=list)

    def send(self, text: str) -> None:
        self.messages.append(text)


class TelegramNotifier:
    """Solo avisos. No se aprueba nada por aquí: los chats de bot de Telegram no van cifrados
    de extremo a extremo y una cuenta comprometida no debe poder mover dinero."""

    def __init__(self, token: str, chat_id: str, api_base: str = "https://api.telegram.org",
                 timeout: float = 10.0):
        u = urlparse(api_base)
        if u.scheme != "https" and not (u.scheme == "http" and u.hostname in {"127.0.0.1", "localhost"}):
            raise ValueError("Telegram exige https (http solo en loopback)")
        self._url = f"{api_base.rstrip('/')}/bot{token}/sendMessage"
        self._chat_id = chat_id
        self._timeout = timeout

    def send(self, text: str) -> None:
        body = json.dumps({"chat_id": self._chat_id, "text": text[:3500]}).encode("utf-8")
        req = urllib.request.Request(self._url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                if resp.status >= 300:
                    raise NotifyError(f"telegram respondió {resp.status}")
        except (urllib.error.URLError, TimeoutError) as exc:
            raise NotifyError(type(exc).__name__) from None   # sin la URL: contiene el token
