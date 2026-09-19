-- =====================================================================
-- Asistente Personal Evolutivo — Fase 0: núcleo seguro
-- Ejecutar como propietario (postgres / rol de servicio). Re-ejecutable.
--
-- Principio: el núcleo se protege con PERMISOS y TRIGGERS de la base de
-- datos, no con instrucciones al modelo.
-- =====================================================================

create extension if not exists pgcrypto;
create extension if not exists vector;

-- Roles de la aplicación (sin contraseña aquí; ver README):
--   alter role ape_agent    password '...';
--   alter role ape_executor password '...';
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'ape_agent') then
    create role ape_agent login;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'ape_executor') then
    create role ape_executor login;
  end if;
end $$;

-- Esquema propio, no expuesto por la API REST de Supabase.
create schema if not exists ape;
revoke all on schema ape from public;
grant usage on schema ape to ape_agent, ape_executor;

-- ---------------------------------------------------------------------
-- Utilidades
-- ---------------------------------------------------------------------
create or replace function ape.deny_mutation() returns trigger
language plpgsql as $$
begin
  raise exception 'ape: % prohibido sobre %', tg_op, tg_table_name
    using errcode = '42501';
end $$;

-- ---------------------------------------------------------------------
-- Auditoría append-only encadenada por hash
-- hash = sha256(prev_hash | ts_utc | db_role | canon)
-- ---------------------------------------------------------------------
create sequence if not exists ape.audit_seq;

create table if not exists ape.audit_event (
  seq       bigint primary key,
  run_id    uuid,
  actor     text not null,          -- declarado por quien escribe
  type      text not null,
  db_role   text not null,          -- fijado por el trigger (session_user)
  ts_utc    text not null,          -- fijado por el trigger
  canon     text not null,          -- JSON canónico del evento (lo que se hashea)
  prev_hash text not null,
  hash      text not null
);

create or replace function ape.audit_before_insert() returns trigger
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
declare last_hash text;
begin
  perform pg_advisory_xact_lock(hashtext('ape.audit_event'));
  select hash into last_hash from ape.audit_event order by seq desc limit 1;
  new.seq       := nextval('ape.audit_seq');
  new.prev_hash := coalesce(last_hash, repeat('0', 64));
  new.db_role   := session_user::text;
  new.ts_utc    := to_char(clock_timestamp() at time zone 'UTC',
                           'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  new.hash      := encode(digest(new.prev_hash || '|' || new.ts_utc || '|' ||
                                 new.db_role || '|' || new.canon, 'sha256'), 'hex');
  return new;
end $$;

drop trigger if exists audit_chain on ape.audit_event;
create trigger audit_chain before insert on ape.audit_event
  for each row execute function ape.audit_before_insert();

drop trigger if exists audit_no_update_delete on ape.audit_event;
create trigger audit_no_update_delete before update or delete on ape.audit_event
  for each row execute function ape.deny_mutation();

drop trigger if exists audit_no_truncate on ape.audit_event;
create trigger audit_no_truncate before truncate on ape.audit_event
  for each statement execute function ape.deny_mutation();

-- Devuelve el seq del primer evento roto, o NULL si la cadena es íntegra.
create or replace function ape.audit_verify() returns bigint
language plpgsql stable security definer
set search_path = ape, extensions, public, pg_catalog as $$
declare r record; prev text := repeat('0', 64); calc text;
begin
  for r in select * from ape.audit_event order by seq loop
    if r.prev_hash <> prev then return r.seq; end if;
    calc := encode(digest(r.prev_hash || '|' || r.ts_utc || '|' ||
                          r.db_role || '|' || r.canon, 'sha256'), 'hex');
    if calc <> r.hash then return r.seq; end if;
    prev := r.hash;
  end loop;
  return null;
end $$;

-- Escritura de eventos desde triggers y funciones internas.
create or replace function ape._audit(p_type text, p_payload jsonb) returns void
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
begin
  insert into ape.audit_event(run_id, actor, type, canon)
  values (null, 'db', p_type,
          jsonb_build_object('type', p_type, 'payload', p_payload)::text);
end $$;

-- Trigger genérico: audita cada cambio (sin args ni embeddings).
create or replace function ape.audit_row() returns trigger
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
declare j jsonb;
begin
  j := case when tg_op = 'DELETE' then to_jsonb(old) else to_jsonb(new) end;
  perform ape._audit(tg_table_name || '.' || lower(tg_op),
                     j - 'args' - 'embedding');
  return null;
end $$;

-- ---------------------------------------------------------------------
-- Núcleo fijo: políticas, herramientas, parada
-- ---------------------------------------------------------------------
create table if not exists ape.core_policy (
  key        text primary key,
  value      jsonb not null,
  sha256     text not null,
  updated_at timestamptz not null default now()
);

create or replace function ape.core_policy_hash() returns trigger
language plpgsql
set search_path = ape, extensions, public, pg_catalog as $$
begin
  new.sha256 := encode(digest(new.value::text, 'sha256'), 'hex');
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists core_policy_hash on ape.core_policy;
create trigger core_policy_hash before insert or update on ape.core_policy
  for each row execute function ape.core_policy_hash();

drop trigger if exists core_policy_audit on ape.core_policy;
create trigger core_policy_audit after insert or update or delete on ape.core_policy
  for each row execute function ape.audit_row();

insert into ape.core_policy(key, value) values
  ('approver',        '"dani"'::jsonb),
  ('max_n2_per_hour', '20'::jsonb)
on conflict (key) do nothing;

create table if not exists ape.tool_spec (
  name           text primary key,
  level          smallint not null check (level between 0 and 3),
  involves_money boolean  not null default false,
  reversible     boolean  not null default true,
  enabled        boolean  not null default true,
  check (not involves_money or level = 3)
);

drop trigger if exists tool_spec_audit on ape.tool_spec;
create trigger tool_spec_audit after insert or update or delete on ape.tool_spec
  for each row execute function ape.audit_row();

create table if not exists ape.kill_switch (
  id         boolean primary key default true check (id),
  active     boolean not null default false,
  reason     text,
  changed_at timestamptz not null default now(),
  changed_by text not null default session_user
);
insert into ape.kill_switch(id) values (true) on conflict do nothing;

drop trigger if exists kill_switch_audit on ape.kill_switch;
create trigger kill_switch_audit after update on ape.kill_switch
  for each row execute function ape.audit_row();

create or replace function ape.kill(p_reason text) returns void
language sql security definer
set search_path = ape, pg_catalog as $$
  update ape.kill_switch
     set active = true, reason = p_reason, changed_at = now(), changed_by = session_user
   where id;
$$;

create or replace function ape.resume() returns void
language sql security definer
set search_path = ape, pg_catalog as $$
  update ape.kill_switch
     set active = false, reason = null, changed_at = now(), changed_by = session_user
   where id;
$$;

-- ---------------------------------------------------------------------
-- Objetivos, memoria, planes, estrategias
-- ---------------------------------------------------------------------
create table if not exists ape.goal (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  definition jsonb not null,
  active     boolean not null default true
);

create table if not exists ape.memory (
  id           uuid primary key default gen_random_uuid(),
  kind         text not null check (kind in ('episodica','semantica','procedimental')),
  content      text not null,
  embedding    vector(768),          -- dimensión pendiente de confirmar
  sensitivity  smallint not null default 2 check (sensitivity between 0 and 2), -- falla cerrado
  source       text not null,
  salience     real not null default 0.5,
  created_at   timestamptz not null default now(),
  last_used_at timestamptz
);
create index if not exists memory_embedding_idx
  on ape.memory using hnsw (embedding vector_cosine_ops);

create table if not exists ape.strategy (
  id         uuid primary key default gen_random_uuid(),
  parent_ids uuid[] not null default '{}',
  generation int not null default 0,
  genome     jsonb not null,
  behavior   jsonb,
  fitness    jsonb,
  status     text not null default 'sombra' check (status in ('sombra','activa','retirada'))
);

create or replace function ape.strategy_guard() returns trigger
language plpgsql as $$
begin
  if session_user in ('ape_agent', 'ape_executor') then
    if tg_op = 'INSERT' then
      new.status := 'sombra';
    elsif new.status = 'activa' and old.status is distinct from 'activa' then
      raise exception 'ape: solo el administrador puede promover una estrategia a activa'
        using errcode = '42501';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists strategy_guard on ape.strategy;
create trigger strategy_guard before insert or update on ape.strategy
  for each row execute function ape.strategy_guard();

drop trigger if exists strategy_audit on ape.strategy;
create trigger strategy_audit after insert or update or delete on ape.strategy
  for each row execute function ape.audit_row();

create table if not exists ape.plan (
  id          uuid primary key default gen_random_uuid(),
  goal_id     uuid references ape.goal(id),
  strategy_id uuid references ape.strategy(id),
  status      text not null default 'abierto',
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Acciones y aprobaciones
-- ---------------------------------------------------------------------
create table if not exists ape.action (
  id              uuid primary key default gen_random_uuid(),
  plan_id         uuid references ape.plan(id),
  tool            text not null references ape.tool_spec(name),
  args            jsonb not null,
  args_hash       text not null,
  level           smallint not null check (level between 0 and 3),
  involves_money  boolean not null default false,
  reversible      boolean not null default true,
  cost_eur        numeric(12,2) not null default 0 check (cost_eur >= 0),
  origin          text not null check (origin in ('dani','agent','external_content')),
  status          text not null default 'propuesta'
                  check (status in ('propuesta','aprobada','ejecutada','fallida','revertida','rechazada')),
  idempotency_key text not null unique,
  created_at      timestamptz not null default now(),
  executed_at     timestamptz,
  check (cost_eur = 0 or involves_money),
  check (not involves_money or level = 3)
);

-- La categoría de una acción la fija el REGISTRO de herramientas, nunca quien la propone.
create or replace function ape.action_before_insert() returns trigger
language plpgsql as $$
declare s ape.tool_spec%rowtype;
begin
  select * into s from ape.tool_spec where name = new.tool and enabled;
  if not found then
    raise exception 'ape: herramienta desconocida o deshabilitada: %', new.tool
      using errcode = '23514';
  end if;
  new.level          := s.level;
  new.reversible     := s.reversible;
  new.involves_money := s.involves_money or new.cost_eur > 0;
  if new.involves_money then new.level := 3; end if;
  if session_user in ('ape_agent', 'ape_executor') then
    new.status := 'propuesta';
  end if;
  return new;
end $$;

drop trigger if exists action_before_insert on ape.action;
create trigger action_before_insert before insert on ape.action
  for each row execute function ape.action_before_insert();

create table if not exists ape.approval (
  id         uuid primary key default gen_random_uuid(),
  action_id  uuid not null references ape.action(id),
  args_hash  text not null,
  approver   text not null,
  amount_eur numeric(12,2) not null check (amount_eur >= 0),
  expires_at timestamptz not null,
  signature  text not null,          -- HMAC; la clave NO está en la base de datos
  created_at timestamptz not null default now()
);

create or replace function ape.action_before_update() returns trigger
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
begin
  if new.plan_id is distinct from old.plan_id or new.tool is distinct from old.tool
     or new.args is distinct from old.args or new.args_hash is distinct from old.args_hash
     or new.level is distinct from old.level
     or new.involves_money is distinct from old.involves_money
     or new.reversible is distinct from old.reversible
     or new.cost_eur is distinct from old.cost_eur or new.origin is distinct from old.origin
     or new.idempotency_key is distinct from old.idempotency_key then
    raise exception 'ape: los campos de una acción son inmutables' using errcode = '42501';
  end if;

  if new.status is distinct from old.status then
    if not ( (old.status = 'propuesta' and new.status in ('aprobada','rechazada','ejecutada','fallida'))
          or (old.status = 'aprobada'  and new.status in ('ejecutada','fallida','rechazada'))
          or (old.status = 'ejecutada' and new.status = 'revertida') ) then
      raise exception 'ape: transición no permitida % -> %', old.status, new.status
        using errcode = '23514';
    end if;

    if new.status = 'ejecutada' then
      if (select active from ape.kill_switch) then
        raise exception 'ape: parada activa, no se ejecuta nada' using errcode = '42501';
      end if;
      if new.level = 3 and not exists (
           select 1 from ape.approval a
            where a.action_id = new.id and a.args_hash = new.args_hash
              and a.expires_at > now() and a.amount_eur >= new.cost_eur) then
        raise exception 'ape: acción N3 sin aprobación válida' using errcode = '42501';
      end if;
      new.executed_at := now();
    end if;
  end if;
  return new;
end $$;

drop trigger if exists action_before_update on ape.action;
create trigger action_before_update before update on ape.action
  for each row execute function ape.action_before_update();

create or replace function ape.approval_before_insert() returns trigger
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
declare a ape.action%rowtype; who text;
begin
  select * into a from ape.action where id = new.action_id;
  if not found then
    raise exception 'ape: la acción no existe' using errcode = '23503';
  end if;
  select value #>> '{}' into who from ape.core_policy where key = 'approver';
  if new.approver is distinct from who then
    raise exception 'ape: aprobador no autorizado' using errcode = '42501';
  end if;
  if new.args_hash is distinct from a.args_hash then
    raise exception 'ape: la aprobación no corresponde a los argumentos de la acción'
      using errcode = '42501';
  end if;
  if new.amount_eur < a.cost_eur then
    raise exception 'ape: importe aprobado inferior al coste' using errcode = '42501';
  end if;
  if new.expires_at <= now() or new.expires_at > now() + interval '7 days' then
    raise exception 'ape: caducidad inválida (máximo 7 días)' using errcode = '23514';
  end if;
  return new;
end $$;

drop trigger if exists approval_before_insert on ape.approval;
create trigger approval_before_insert before insert on ape.approval
  for each row execute function ape.approval_before_insert();

drop trigger if exists approval_no_change on ape.approval;
create trigger approval_no_change before update or delete on ape.approval
  for each row execute function ape.deny_mutation();

drop trigger if exists approval_audit on ape.approval;
create trigger approval_audit after insert on ape.approval
  for each row execute function ape.audit_row();

drop trigger if exists action_audit_ins on ape.action;
create trigger action_audit_ins after insert on ape.action
  for each row execute function ape.audit_row();

create or replace function ape.action_audit_status() returns trigger
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
begin
  if new.status is distinct from old.status then
    perform ape._audit('action.status',
      jsonb_build_object('id', new.id, 'tool', new.tool, 'level', new.level,
                         'from', old.status, 'to', new.status,
                         'args_hash', new.args_hash, 'cost_eur', new.cost_eur));
  end if;
  return null;
end $$;

drop trigger if exists action_audit_upd on ape.action;
create trigger action_audit_upd after update on ape.action
  for each row execute function ape.action_audit_status();

-- Libro de gasto: se rellena solo al ejecutar una acción con coste.
create table if not exists ape.budget_ledger (
  id          uuid primary key default gen_random_uuid(),
  action_id   uuid not null references ape.action(id),
  amount_eur  numeric(12,2) not null,
  approved_by text not null,
  ts          timestamptz not null default now()
);

create or replace function ape.ledger_after_update() returns trigger
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
declare who text;
begin
  if new.status = 'ejecutada' and old.status is distinct from 'ejecutada' and new.cost_eur > 0 then
    select a.approver into who from ape.approval a
     where a.action_id = new.id order by a.created_at desc limit 1;
    insert into ape.budget_ledger(action_id, amount_eur, approved_by)
    values (new.id, new.cost_eur, coalesce(who, 'desconocido'));
  end if;
  return null;
end $$;

drop trigger if exists ledger_after_update on ape.action;
create trigger ledger_after_update after update on ape.action
  for each row execute function ape.ledger_after_update();

-- ---------------------------------------------------------------------
-- Permisos mínimos
-- ---------------------------------------------------------------------
revoke all on all tables    in schema ape from public;
revoke all on all sequences in schema ape from public;
revoke all on all functions in schema ape from public;

-- El agente (el ciclo que razona): lee el núcleo, propone, recuerda.
grant select on ape.core_policy, ape.tool_spec, ape.kill_switch, ape.goal to ape_agent;
grant select, insert, update, delete on ape.memory to ape_agent;
grant select, insert, update on ape.plan, ape.strategy to ape_agent;
grant select, insert on ape.action to ape_agent;
grant select, insert on ape.audit_event to ape_agent, ape_executor;
grant execute on function ape.audit_verify() to ape_agent, ape_executor;

-- El ejecutor (pasarela de herramientas): solo cambia el estado de acciones.
grant select on ape.core_policy, ape.tool_spec, ape.kill_switch, ape.plan to ape_executor;
grant select on ape.action to ape_executor;
grant update (status) on ape.action to ape_executor;

-- Nadie salvo el propietario puede:
--   modificar core_policy, tool_spec, kill_switch, goal
--   insertar en approval o budget_ledger
--   ejecutar ape.kill() / ape.resume()
