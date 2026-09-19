"""Carga de configuración desde un JSON. Las claves NUNCA van en el JSON: solo el nombre de la
variable de entorno que las contiene."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .classification import Endpoint, EndpointKind
from .notify import ConsoleNotifier, Notifier, TelegramNotifier
from .router import LLMEndpoint, Router


class ConfigError(RuntimeError):
    pass


def _env(name: str) -> str:
    val = os.environ.get(name, "")
    if not val:
        raise ConfigError(f"falta la variable de entorno {name}")
    return val


def load_router(cfg: dict) -> Router:
    endpoints = []
    for e in cfg.get("endpoints", []):
        try:
            kind = EndpointKind(e["kind"])
            key = os.environ.get(e["api_key_env"], "") if e.get("api_key_env") else ""
            if kind != EndpointKind.LOCAL and not key:
                raise ConfigError(f"falta la clave de {e['name']} ({e.get('api_key_env')})")
            endpoints.append(LLMEndpoint(
                Endpoint(e["name"], kind, bool(e.get("privacy_reviewed", False))),
                e["base_url"], e["model"], key, float(e.get("timeout", 30))))
        except KeyError as exc:
            raise ConfigError(f"endpoint mal definido, falta {exc}") from None
    return Router(endpoints)


def load_notifier(cfg: dict) -> Notifier:
    t = cfg.get("telegram")
    if not t:
        return ConsoleNotifier()
    return TelegramNotifier(_env(t["token_env"]), _env(t["chat_id_env"]))


def load_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))
