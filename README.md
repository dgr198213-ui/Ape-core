# ape-core — Fase 0 del Asistente Personal Evolutivo

Núcleo seguro sobre el que se construye el resto del agente. **Sin él no se activa ninguna iniciativa.**

## Qué contiene

| Pieza | Dónde | Qué garantiza |
|---|---|---|
| Esquema y permisos | `migrations/0001_core.sql` | El agente no puede tocar políticas, herramientas, aprobaciones ni la parada |
| Registro de herramientas | `migrations/0002_seed_tools.sql` | El nivel (N0–N3) y si implica dinero lo fija el registro, no quien propone |
| Motor de políticas | `src/ape/policy.py` | Determinista, sin LLM. Todo lo que implique dinero o sea N3 exige aprobación firmada de Dani |
| Aprobaciones firmadas | `policy.py` | HMAC ligado a acción, argumentos, importe y caducidad. La clave no está en la BD |
| Auditoría | `migrations` + `src/ape/audit.py` | Append-only, encadenada por hash, calculada por la BD, verificable desde fuera |
| Parada | `ape.kill()` / `ape.resume()` | Con la parada activa la BD rechaza cualquier ejecución |
| Clasificación de datos | `src/ape/classification.py` | Los datos sensibles nunca salen a endpoints remotos; lo desconocido falla cerrado |
| CI y copias | `.github/workflows` | Pruebas en cada push; verificación diaria de la cadena y copia cifrada |

## Estado de verificación

- **78 pruebas en verde** (38 unitarias y de propiedades + 40 de integración) contra **PostgreSQL 16.15 con pgvector 0.6.0 reales**.
- Se probó por **mutación**: al quitar la exigencia de aprobación en la BD y en el motor, las pruebas fallan (5 fallos).
- **Desplegado y verificado en Supabase** (proyecto `ape-core`, `eu-central-1`, plan gratuito, PostgreSQL 17, pgvector 0.8.2), 19-sep-2026:
  - Las 14 funciones del esquema tienen el mismo hash que las de la base local construida desde estos archivos.
  - Pruebas de comportamiento en la base real (con marcha atrás): nivel fijado por el registro, N3 sin aprobación rechazado, aprobaciones inválidas rechazadas, libro de gasto, parada, auditoría íntegra e inmutable, memoria vectorial. Todas correctas.
  - Privilegios por catálogo: el agente y el ejecutor no tienen ningún privilegio de escritura sobre el núcleo; el ejecutor solo puede actualizar la columna `status`; nadie salvo el propietario puede ejecutar `ape.kill()`; los roles de la API (`anon`, `authenticated`, `service_role`) no tienen acceso al esquema `ape`.
  - Avisos de seguridad de Supabase: 0 tras `0003_hardening.sql` (antes había 4).
- **Cabeza de la auditoría anclada** (11 eventos, 19-sep-2026): `4390fe91774e6a6eef402ec08c5fe229735b4d4d0d97b6f1bc501b9f6e5f669a`. Cualquier recorte del final de la cadena cambiaría este valor.
- **No verificado:**
  - Los workflows de GitHub (`ci.yml`, `nightly.yml`) y la conexión desde Actions a Supabase (la conexión directa puede requerir IPv6; si falla, usar la cadena del *pooler*).
  - El comportamiento *con los roles reales* `ape_agent` y `ape_executor` en Supabase. El conector no permite conectarse como ellos, así que los triggers que dependen de `session_user` (estado forzado a `propuesta`, estrategias en sombra, rol registrado en la auditoría) solo se han probado en la base local, no en la de Supabase.
  - Que la actividad del workflow nocturno evite la pausa por inactividad del plan gratuito.

## Despliegue

1. **Repositorio privado** nuevo con este contenido. Activa el escaneo de secretos.
2. **Base de datos:** ya aplicada en `ape-core` (migraciones 0001, 0002, 0003 y 0003b). Para otra instalación (Postgres 15+ con `pgvector` y `pgcrypto`):
   ```sh
   DATABASE_URL_ADMIN='postgresql://...' ./scripts/apply_migrations.sh
   ```
   En Supabase, comprueba que el esquema `ape` **no** está en *Settings → API → Exposed schemas*.
3. **Contraseñas de los roles** — *pendiente, hazlo tú en el editor SQL de Supabase para que no pasen por ningún chat* (una para cada uno, distintas y largas):
   ```sql
   alter role ape_agent    password '...';
   alter role ape_executor password '...';
   ```
4. **Clave de aprobaciones** (no va en la base de datos ni en el proceso del agente):
   ```sh
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   Guárdala solo donde corra el ejecutor y el servicio de aprobación.
5. **Secretos de GitHub:** `DATABASE_URL_ADMIN` y `AGE_PUBLIC_KEY` (`age-keygen`, guarda la clave privada fuera de GitHub).
6. **Pruebas locales:**
   ```sh
   pip install -e ".[dev]"
   pytest                                   # unitarias y propiedades
   APE_TEST_DSN=postgresql://postgres:...@127.0.0.1:5432/postgres pytest   # + integración
   ```

## Fronteras de confianza

| Quién | Puede | No puede |
|---|---|---|
| `ape_agent` (ciclo que razona) | Leer el núcleo, proponer acciones, escribir memoria y estrategias en sombra | Aprobar, ejecutar, cambiar políticas, parar/reanudar, promover estrategias |
| `ape_executor` (pasarela) | Cambiar el estado de acciones | Cambiar argumentos, coste o nivel; ejecutar sin aprobación o con la parada activa |
| Dani (propietario / servicio de aprobación) | Todo lo anterior, `ape.kill()`, aprobaciones | — |

## Limitaciones conocidas

- La BD comprueba que existe una aprobación ligada a la acción, pero **no** verifica la firma HMAC (no tiene la clave). La firma la verifica el motor de Python en el ejecutor: **el ejecutor debe llamar siempre al motor antes de ejecutar.**
- Un propietario con acceso total puede desactivar triggers. La verificación de la cadena lo delata, pero **recortar el final** de la auditoría solo se detecta comparando con la cabeza anclada fuera de la BD (la registra `nightly.yml`).
- El nivel de una acción sale del registro `tool_spec`; **registrar una herramienta mal clasificada** (p. ej. un pago marcado como N1) rompe la protección. Revisa cada herramienta nueva a mano.
- La dimensión del embedding (768) está por confirmar.

## Siguiente: Fase 1

Memoria con olvido activo, ciclo programado que solo percibe y propone, y el canal con Dani (aprobar y `/kill`).
