"""Serialización canónica y hashes compartidos por el motor de políticas y la auditoría."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any


def canonical_json(obj: Any) -> str:
    """JSON determinista: claves ordenadas, sin espacios, UTF-8 sin escapar."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def args_hash(args: Any) -> str:
    """Hash de los argumentos de una acción. La aprobación queda ligada a este valor."""
    return sha256_hex(canonical_json(args))


def secret_bytes(raw: str) -> bytes:
    """Clave de aprobaciones a partir de una cadena. Si es hexadecimal se decodifica; si no, se usa
    su texto UTF-8 (así vale cualquier cadena larga de un gestor de contraseñas). Mínimo 32 caracteres.
    El panel, la CLI y el ejecutor DEBEN usar esta misma función."""
    import re
    raw = (raw or "").strip()
    if len(raw) < 32:
        raise ValueError("la clave de aprobaciones debe tener al menos 32 caracteres")
    if re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) % 2 == 0:
        return bytes.fromhex(raw)
    return raw.encode("utf-8")


def money(amount: Decimal | int | str) -> str:
    """Importe con dos decimales, formato estable para firmar."""
    return format(Decimal(amount).quantize(Decimal("0.01")), "f")


def iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("se exige una fecha con zona horaria")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
