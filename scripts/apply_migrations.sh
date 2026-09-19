#!/usr/bin/env sh
# Aplica las migraciones en orden. Uso: DATABASE_URL_ADMIN=... ./scripts/apply_migrations.sh
set -eu
: "${DATABASE_URL_ADMIN:?define DATABASE_URL_ADMIN con el usuario propietario}"
for f in migrations/*.sql; do
  echo ">> $f"
  psql "$DATABASE_URL_ADMIN" -v ON_ERROR_STOP=1 -q -f "$f"
done
echo "OK"
