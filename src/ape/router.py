"""Router de modelos por clase de dato.

Habla el protocolo de chat compatible con OpenAI (POST {base_url}/chat/completions), que
ofrecen tanto modelos locales (Ollama, llama.cpp) como varios proveedores remotos.
Falla cerrado: si ningún endpoint es elegible para la clase de dato, NO se llama a nadie.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from .classification import DataClass, Endpoint, EndpointKind, eligible

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class NoEligibleEndpoint(RuntimeError):
    """Ningún endpoint puede recibir datos de esta clase."""


class LLMError(RuntimeError):
    """Todos los endpoints elegibles fallaron (los mensajes no incluyen claves ni contenido)."""


@dataclass(frozen=True)
class LLMEndpoint:
    endpoint: Endpoint
    base_url: str
    model: str
    api_key: str = field(default="", repr=False)
    timeout: float = 30.0

    def __post_init__(self) -> None:
        u = urlparse(self.base_url)
        if u.scheme != "https" and not (u.scheme == "http" and u.hostname in _LOOPBACK):
            raise ValueError("los endpoints remotos deben usar https (http solo en loopback)")
        if not self.model:
            raise ValueError("falta el modelo del endpoint " + self.endpoint.name)


@dataclass(frozen=True)
class Completion:
    text: str
    endpoint: str


class Router:
    def __init__(self, endpoints: list[LLMEndpoint]):
        self._endpoints = list(endpoints)

    def eligible(self, data_class: DataClass) -> list[LLMEndpoint]:
        names = {e.name for e in eligible(data_class, [x.endpoint for x in self._endpoints])}
        return [x for x in self._endpoints if x.endpoint.name in names]

    def max_class(self) -> int:
        """Clase de dato más alta que algún endpoint puede recibir; -1 si no hay ninguno."""
        for cls in (DataClass.SENSITIVE, DataClass.PERSONAL, DataClass.PUBLIC):
            if self.eligible(cls):
                return int(cls)
        return -1

    def complete(self, system: str, user: str, data_class: DataClass) -> Completion:
        candidates = self.eligible(data_class)
        if not candidates:
            raise NoEligibleEndpoint(f"sin endpoint elegible para datos de clase {int(data_class)}")
        errors: list[str] = []
        for ep in candidates:
            try:
                return Completion(self._call(ep, system, user), ep.endpoint.name)
            except (urllib.error.URLError, TimeoutError, ValueError, KeyError, IndexError,
                    json.JSONDecodeError) as exc:
                errors.append(f"{ep.endpoint.name}: {type(exc).__name__}")
        raise LLMError("; ".join(errors))

    @staticmethod
    def _call(ep: LLMEndpoint, system: str, user: str) -> str:
        body = json.dumps({
            "model": ep.model, "temperature": 0,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if ep.api_key:
            headers["Authorization"] = "Bearer " + ep.api_key
        req = urllib.request.Request(ep.base_url.rstrip("/") + "/chat/completions",
                                     data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=ep.timeout) as resp:  # noqa: S310 (esquema validado)
            data = json.loads(resp.read().decode("utf-8"))
        text = data["choices"][0]["message"]["content"]
        if not isinstance(text, str):
            raise ValueError("respuesta sin texto")
        return text
