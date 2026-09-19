"""Cadena de auditoría append-only.

hash = sha256(prev_hash | ts_utc | db_role | canon)

La base de datos calcula prev_hash, ts, db_role y hash con un trigger; el cliente solo
aporta `canon`. Este módulo verifica la cadena desde fuera (defensa en profundidad).

Limitación conocida: recortar el FINAL de la cadena no se detecta desde dentro.
Se mitiga anclando la cabeza (`head`) fuera de la base de datos (aviso diario a Dani).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .canon import canonical_json, sha256_hex

GENESIS = "0" * 64


def event_canon(actor: str, type_: str, payload: Any, run_id: Optional[str] = None) -> str:
    return canonical_json({"actor": actor, "type": type_, "run_id": run_id, "payload": payload})


def compute_hash(prev_hash: str, ts_utc: str, db_role: str, canon: str) -> str:
    return sha256_hex(f"{prev_hash}|{ts_utc}|{db_role}|{canon}")


@dataclass(frozen=True)
class AuditRow:
    seq: int
    ts_utc: str
    db_role: str
    canon: str
    prev_hash: str
    hash: str


def verify_chain(rows: Iterable[AuditRow]) -> Optional[int]:
    """Devuelve el seq del primer evento roto, o None si la cadena es íntegra."""
    prev = GENESIS
    last_seq = -1
    for row in sorted(rows, key=lambda r: r.seq):
        if row.seq <= last_seq:
            return row.seq
        if row.prev_hash != prev:
            return row.seq
        if compute_hash(row.prev_hash, row.ts_utc, row.db_role, row.canon) != row.hash:
            return row.seq
        prev = row.hash
        last_seq = row.seq
    return None


def head(rows: Iterable[AuditRow]) -> str:
    rows = sorted(rows, key=lambda r: r.seq)
    return rows[-1].hash if rows else GENESIS


def verify_head(rows: Iterable[AuditRow], expected_head: str) -> bool:
    """Comprueba que la cadena es íntegra y termina en una cabeza esperada.

    La verificación de la cadena por sí sola no detecta que se hayan eliminado
    eventos del final. Comparar la cabeza calculada con un valor anclado fuera
    de la base de datos sí detecta ese recorte.
    """
    if verify_chain(rows) is not None:
        return False
    return head(rows) == expected_head
