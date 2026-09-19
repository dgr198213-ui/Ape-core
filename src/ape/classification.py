"""Clasificación de datos y enrutado a modelos.

Regla de fondo: lo que se envía a un endpoint gratuito puede ser reutilizado por el
proveedor. Los datos sensibles (clase 2) NUNCA salen a endpoints remotos.
Falla cerrado: lo desconocido se trata como clase 2.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Iterable, Optional


class DataClass(IntEnum):
    PUBLIC = 0      # noticias, documentación
    PERSONAL = 1    # agenda, preferencias
    SENSITIVE = 2   # situación económica, cuentas, salud


class EndpointKind(str, Enum):
    LOCAL = "local"
    REMOTE_FREE = "remote_free"
    REMOTE_PAID = "remote_paid"


@dataclass(frozen=True)
class Endpoint:
    name: str
    kind: EndpointKind
    privacy_reviewed: bool = False  # Dani ha leído y aceptado sus términos de datos


def normalize(value: Optional[int]) -> DataClass:
    """Cualquier valor desconocido o ausente es SENSITIVE."""
    try:
        return DataClass(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return DataClass.SENSITIVE


def combined_class(classes: Iterable[Optional[int]]) -> DataClass:
    """Un contexto vale lo que su fragmento más sensible. Un contexto vacío es PUBLIC."""
    result = DataClass.PUBLIC
    for c in classes:
        result = max(result, normalize(c))
    return result


def eligible(data_class: DataClass, endpoints: Iterable[Endpoint]) -> list[Endpoint]:
    out = []
    for e in endpoints:
        if data_class == DataClass.SENSITIVE:
            ok = e.kind == EndpointKind.LOCAL
        elif data_class == DataClass.PERSONAL:
            ok = e.kind == EndpointKind.LOCAL or e.privacy_reviewed
        else:
            ok = True
        if ok:
            out.append(e)
    return out
