# ape-core — Asistente Personal Evolutivo (Fases 0 y 1 + panel móvil)

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

- **207 pruebas en verde** (incluida una prueba de la interfaz móvil con jsdom contra el servidor real) contra **PostgreSQL 16.15 con pgvector 0.6.0 reales**, incluidos servidores HTTP reales en loopback para el router y Telegram, y la CLI ejecutada como proceso.
- Se probó por **mutación** (15 mutaciones: aprobación en la BD y en el motor, elegibilidad del router, contaminación por origen externo, firma con hash falso, suelo de sensibilidad, escape de `<untrusted>`, y en el panel: CSRF, código de un solo uso, TOTP reutilizable, guardia SQL, `HttpOnly`, bloqueo por intentos, `Origin`, lectura de memoria): las pruebas detectan todas.
- **Desplegado y verificado en Supabase** (proyecto `ape-core`, `eu-central-1`, plan gratuito, PostgreSQL 17, pgvector 0.8.2), 19-sep-2026, migraciones 0001–0005:
  - Las 20 funciones del esquema tienen el mismo código, `SECURITY DEFINER` y `search_path` que las de la base local construida desde estos archivos.
  - Pruebas de comportamiento en la base real (con marcha atrás): nivel fijado por el registro, N3 sin aprobación rechazado, aprobaciones inválidas rechazadas, libro de gasto, parada, auditoría íntegra e inmutable, memoria vectorial. Todas correctas.
  - Privilegios por catálogo: el agente y el ejecutor no tienen ningún privilegio de escritura sobre el núcleo; el ejecutor solo puede actualizar la columna `status`; nadie salvo el propietario puede ejecutar `ape.kill()`; los roles de la API (`anon`, `authenticated`, `service_role`) no tienen acceso al esquema `ape`.
  - Avisos de seguridad de Supabase: 0 tras `0003_hardening.sql` (antes había 4).
- **Cabeza de la auditoría anclada** (14 eventos, 19-sep-2026, tras la Fase 1): `3cc05a995b96ac96b3f89226dd9b0049a09f96813ce098c5c56ce7cd0f7634f4` (la anterior, con 11 eventos: `4390fe91…f669a`). Cualquier recorte del final de la cadena cambiaría este valor.
- **No verificado:**
  - **El panel desplegado en Vercel.** Está probado en local (servidor real, PostgreSQL real, interfaz en jsdom), pero no en un navegador de móvil ni en el runtime de Vercel; el primer despliegue puede pedir ajustes.
  - **La conexión a Supabase a través del *pooler*** desde Vercel y desde GitHub Actions (el diseño ya evita sentencias preparadas, pero no lo he podido probar).
  - **Las llamadas reales a los proveedores de modelos y a Telegram.** El entorno de pruebas no tiene salida a esas redes: el router y el notificador solo se han probado contra servidores simulados en loopback.
  - **El ciclo no está programado todavía** (falta el disparador periódico) y **no hay proveedor de embeddings**: sin él, la recuperación de memoria usa la puntuación y no la similitud.
  - Los workflows de GitHub (`ci.yml`, `nightly.yml`) y la conexión desde Actions a Supabase (la conexión directa puede requerir IPv6; si falla, usar la cadena del *pooler*).
  - El comportamiento *con los roles reales* `ape_agent` y `ape_executor` en Supabase. El conector no permite conectarse como ellos, así que los triggers que dependen de `session_user` (estado forzado a `propuesta`, estrategias en sombra, rol registrado en la auditoría) solo se han probado en la base local, no en la de Supabase.
  - Que la actividad del workflow nocturno evite la pausa por inactividad del plan gratuito.

## Puesta en marcha (en este orden)

Dónde vive cada pieza: **Supabase** (memoria y reglas) · **Vercel** (el panel web que abres en el móvil) · **GitHub Actions** (el ciclo que hace pensar al agente cada hora) · **tu equipo** (opcional: la CLI).

| # | Qué | Dónde | Desde el móvil |
|---|---|---|---|
| 1 | Subir este código a `dgr198213-ui/Ape-core` (`git push`) | GitHub | ❌ una vez desde un PC |
| 2 | Ponerles contraseña a los roles: `alter role ape_panel password '...'; alter role ape_agent password '...';` | Supabase → SQL Editor | ✅ |
| 3 | Copiar las cadenas de conexión del *pooler* (Connect → Transaction pooler). El usuario es `ape_panel.<ref-del-proyecto>` y `ape_agent.<ref-del-proyecto>` | Supabase | ✅ |
| 4 | Variables de entorno del proyecto `ape-core`: `APE_PANEL_DSN` (rol `ape_panel`), `APE_APPROVAL_SECRET` (cadena aleatoria de 32+ caracteres del gestor de contraseñas), `APE_SETUP_TOKEN` (otra cadena aleatoria, de un solo uso) | Vercel → Settings → Environment Variables | ✅ |
| 5 | Redesplegar. Abre la URL en el móvil → **configurar**: código de configuración, frase de paso y clave para tu app de autenticación | Navegador | ✅ |
| 6 | «Añadir a pantalla de inicio» | Navegador | ✅ |
| 7 | Secretos del repositorio: `APE_DSN_AGENT`, `APE_CONFIG_JSON` (ver `config.example.json`), claves de los modelos | GitHub → Settings → Secrets | ✅ |
| 8 | Opcional: botón «Ejecutar ciclo ahora»: `APE_GITHUB_TOKEN` (token fino con permiso *Actions: write* solo sobre este repo) y `APE_GITHUB_REPO=dgr198213-ui/Ape-core` en Vercel | Vercel / GitHub | ✅ |

**Para reiniciar el acceso al panel** (si pierdes el móvil): en el editor SQL de Supabase, `delete from ape.panel_auth; delete from ape.panel_session;` y vuelve a configurar con un `APE_SETUP_TOKEN` nuevo.

## El panel web

Pantalla de inicio en el móvil, sin instalar nada. Cuatro pestañas: **Resumen** (estado, ciclo, auditoría), **Hablar** (mensaje al agente), **Pendientes** (aprobar o rechazar con un código nuevo de tu app) e **Historial**. El botón **PARAR** está siempre arriba y no pide código; **reanudar** sí.

| Amenaza | Defensa |
|---|---|
| Alguien adivina el acceso | Frase de paso (scrypt) + código TOTP de un solo uso; bloqueo tras 5 fallos; el mismo mensaje de error para cualquier fallo |
| Robo de sesión | Cookie `__Host-` `HttpOnly` `Secure` `SameSite=Strict`, guardada hasheada en la BD, caduca a los 30 min de inactividad y a las 12 h |
| Petición desde otra web (CSRF) | Token por sesión en cabecera + comprobación de `Origin` |
| Contenido del agente con código malicioso | La interfaz pinta todo como texto (nunca HTML); política CSP sin `unsafe-inline`; una prueba impide `innerHTML`/`eval` |
| Panel comprometido | El rol `ape_panel` solo puede: escribir en la bandeja, aprobar/rechazar propuestas, parar y leer. No puede cambiar políticas, herramientas, leer la memoria, ejecutar ni tocar la auditoría |
| Aprobar algo distinto de lo mostrado | La aprobación va ligada a los argumentos por hash; el ejecutor la rechaza si cambian |


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

- **Fase 1b:** proveedor de embeddings y percepción de fuentes reales (correo, calendario). El disparador periódico ya está en `.github/workflows/cycle.yml`.
- **Fase 2:** ejecutor con herramientas N0–N2 vía MCP; las N3 solo con aprobación válida.
