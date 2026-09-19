-- =====================================================================
-- Panel web de Dani (móvil): rol propio con privilegios mínimos.
-- El panel puede: escribir en la bandeja, ver y aprobar/rechazar acciones N3,
-- parar/reanudar y leer la auditoría. NO puede: cambiar políticas, herramientas
-- ni la aprobación de gasto, leer la memoria, ejecutar acciones ni tocar la auditoría.
-- =====================================================================

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'ape_panel') then
    create role ape_panel login;   -- contraseña: alter role ape_panel password '...';
  end if;
end $$;

grant usage on schema ape to ape_panel;
alter role ape_panel set search_path = ape, extensions, public, pg_catalog;

-- Credenciales del panel (una sola persona). Para reiniciarlas:  delete from ape.panel_auth;  (como propietario)
create table if not exists ape.panel_auth (
  id             boolean primary key default true check (id),
  pass_hash      text   not null,
  pass_salt      text   not null,
  totp_secret    text   not null,
  totp_last_step bigint not null default 0,
  created_at     timestamptz not null default now()
);

create table if not exists ape.panel_session (
  token_hash text primary key,
  created_at timestamptz not null default now(),
  last_seen  timestamptz not null default now(),
  expires_at timestamptz not null
);

create table if not exists ape.panel_attempt (
  id   bigserial primary key,
  ts   timestamptz not null default now(),
  kind text not null,
  ok   boolean not null,
  ip   text
);
create index if not exists panel_attempt_ts_idx on ape.panel_attempt (kind, ts);

revoke all on table ape.panel_auth, ape.panel_session, ape.panel_attempt from public;
revoke all on sequence ape.panel_attempt_id_seq from public;

grant select, insert on ape.panel_auth to ape_panel;
grant update (totp_last_step) on ape.panel_auth to ape_panel;
grant select, insert, update, delete on ape.panel_session to ape_panel;
grant select, insert, delete on ape.panel_attempt to ape_panel;
grant usage on sequence ape.panel_attempt_id_seq to ape_panel;

-- Lectura de lo que Dani debe ver.
grant select on ape.action, ape.approval, ape.kill_switch, ape.core_policy, ape.tool_spec,
                ape.inbox, ape.audit_event to ape_panel;

-- Escritura acotada.
grant insert on ape.inbox to ape_panel;                    -- from_dani = true lo fija la BD
grant insert on ape.approval to ape_panel;                 -- la BD valida aprobador, hash, importe y caducidad
grant update (status) on ape.action to ape_panel;

grant execute on function ape.kill(text), ape.resume(), ape.audit_verify(),
                          ape._audit(text, jsonb) to ape_panel;

-- El panel solo puede aprobar o rechazar; nunca marcar una acción como ejecutada.
create or replace function ape.action_panel_guard() returns trigger
language plpgsql
set search_path = ape, extensions, public, pg_catalog as $$
begin
  if session_user = 'ape_panel' and new.status is distinct from old.status
     and new.status not in ('aprobada', 'rechazada') then
    raise exception 'ape: el panel solo puede aprobar o rechazar' using errcode = '42501';
  end if;
  return new;
end $$;

drop trigger if exists action_panel_guard on ape.action;
create trigger action_panel_guard before update on ape.action
  for each row execute function ape.action_panel_guard();
