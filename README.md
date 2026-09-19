# ape-core — Fases 0 y 1 del Asistente Personal Evolutivo

Fase 0: núcleo seguro. Fase 1: memoria con olvido activo, bandeja de entrada, ciclo que **percibe, recuerda, planifica y propone (nunca ejecuta)**, aprobaciones y parada desde la línea de comandos.

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

## Fase 1: qué añade

| Pieza | Dónde | Qué garantiza |
|---|---|---|
| Memoria con suelo de sensibilidad | `0004_*.sql` | La política (`source_min_sensitivity`) fija la clase mínima por origen; un origen desconocido es clase 2. El agente no puede rebajarla, reescribir recuerdos ni fijarlos |
| Olvido activo | `ape.memory_forget()` | Si se supera `memory_max_rows`, conserva los de mayor `salience × 0,5^(días/vida media)` hasta el 90 %; lo fijado nunca se olvida |
| Bandeja de entrada | `ape.inbox` | La BD marca si el mensaje es de Dani o externo; el agente no puede hacerse pasar por Dani |
| Router de modelos | `router.py` | Falla cerrado: sin endpoint elegible para la clase del dato, no sale ni una petición |
| Planificador | `planner.py` | El modelo solo emite JSON; el contenido de terceros va en bloques `<untrusted>` que no pueden cerrarse |
| Ciclo | `cycle.py` | Solo propone. Corre sin la clave de aprobaciones. Todo lo derivado de contenido externo queda marcado `external_content` |
| Administración | `admin.py`, `cli.py` | Aprobar (con confirmación del id), rechazar, parar, reanudar, verificar la cadena |

## Uso diario (`ape --help`)

```sh
export APE_DSN_ADMIN='postgresql://...'      # tu conexión de propietario
ape say "revisa oportunidades de ingresos sin capital"   # deja un mensaje al agente
ape pending                                  # acciones N3 que esperan tu aprobación (con sus argumentos)
APE_APPROVAL_SECRET=<hex> ape approve <id>   # pide escribir los 8 primeros caracteres del id
ape reject <id>
ape kill "motivo"                            # PARADA inmediata
ape resume
ape audit-verify
APE_DSN_AGENT=... APE_CONFIG=config.json ape cycle   # un ciclo (solo propone)
```

**Configuración de modelos:** copia `config.example.json` a `config.json`, sustituye `<MODELO>` y define las variables de entorno con las claves. Las URL de Gemini y Z.ai son las de sus interfaces compatibles con OpenAI **según mi conocimiento, sin verificar**: compruébalas en su documentación. Por defecto ningún endpoint remoto está marcado `privacy_reviewed`, así que **solo recibe datos de clase 0 (públicos)**. Los mensajes que escribes tú (`manual_dani`) son clase 1: hasta que revises los términos de datos de un proveedor y lo marques `privacy_reviewed: true`, o tengas un modelo local, el agente los guarda pero no los procesa.

## Estado de verificación

- **150 pruebas en verde** contra **PostgreSQL 16.15 con pgvector 0.6.0 reales**, incluidos servidores HTTP reales en loopback para el router y Telegram, y la CLI ejecutada como proceso.
- Se probó por **mutación** (7 mutaciones: aprobación en la BD y en el motor, elegibilidad del router, contaminación por origen externo, firma con hash falso, suelo de sensibilidad, escape de `<untrusted>`): las pruebas fallan en todas (22 fallos en total).
- **Desplegado y verificado en Supabase** (proyecto `ape-core`, `eu-central-1`, plan gratuito, PostgreSQL 17, pgvector 0.8.2), 19-sep-2026, migraciones 0001–0004:
  - Las 19 funciones del esquema tienen el mismo código, `SECURITY DEFINER` y `search_path` que las de la base local construida desde estos archivos.
  - Pruebas de comportamiento en la base real (con marcha atrás): nivel fijado por el registro, N3 sin aprobación rechazado, aprobaciones inválidas rechazadas, libro de gasto, parada, auditoría íntegra e inmutable, memoria vectorial. Todas correctas.
  - Privilegios por catálogo: el agente y el ejecutor no tienen ningún privilegio de escritura sobre el núcleo; el ejecutor solo puede actualizar la columna `status`; nadie salvo el propietario puede ejecutar `ape.kill()`; los roles de la API (`anon`, `authenticated`, `service_role`) no tienen acceso al esquema `ape`.
  - Avisos de seguridad de Supabase: 0 tras `0003_hardening.sql` (antes había 4).
- **Cabeza de la auditoría anclada** (14 eventos, 19-sep-2026, tras la Fase 1): `3cc05a995b96ac96b3f89226dd9b0049a09f96813ce098c5c56ce7cd0f7634f4` (la anterior, con 11 eventos: `4390fe91…f669a`). Cualquier recorte del final de la cadena cambiaría este valor.
- **No verificado:**
  - **Las llamadas reales a los proveedores de modelos y a Telegram.** El entorno de pruebas no tiene salida a esas redes: el router y el notificador solo se han probado contra servidores simulados en loopback.
  - **El ciclo no está programado todavía** (falta el disparador periódico) y **no hay proveedor de embeddings**: sin él, la recuperación de memoria usa la puntuación y no la similitud.
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

## Siguiente

- **Fase 1b:** disparador periódico del ciclo, proveedor de embeddings y percepción de fuentes reales (correo, calendario).
- **Fase 2:** ejecutor con herramientas N0–N2 vía MCP; las N3 solo con aprobación válida.
