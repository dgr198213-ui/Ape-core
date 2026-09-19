-- =====================================================================
-- Fase 1: memoria con olvido activo y bandeja de entrada
-- =====================================================================

-- ---------------------------------------------------------------------
-- Memoria: la sensibilidad mínima la fija la POLÍTICA según el origen.
-- Un origen desconocido se trata como clase 2 (falla cerrado).
-- ---------------------------------------------------------------------
alter table ape.memory add column if not exists pinned   boolean not null default false;
alter table ape.memory add column if not exists external boolean not null default false;

insert into ape.core_policy(key, value) values
  ('source_min_sensitivity',
   '{"manual_dani":1,"inbox":1,"calendar":1,"web_public":0,"gmail":2,"finance":2,"health":2}'::jsonb),
  ('memory_max_rows',       '5000'::jsonb),
  ('memory_half_life_days', '30'::jsonb)
on conflict (key) do nothing;

create or replace function ape.memory_guard() returns trigger
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
declare m jsonb; floor_class smallint;
begin
  select value into m from ape.core_policy where key = 'source_min_sensitivity';
  floor_class := coalesce((m ->> new.source)::smallint, 2);
  new.sensitivity := greatest(new.sensitivity, floor_class);
  if session_user in ('ape_agent', 'ape_executor') then
    new.pinned := false;          -- solo el propietario puede fijar recuerdos
  end if;
  return new;
end $$;

drop trigger if exists memory_guard on ape.memory;
create trigger memory_guard before insert on ape.memory
  for each row execute function ape.memory_guard();

-- El agente ya no borra directamente ni cambia contenido, origen ni sensibilidad.
revoke delete on ape.memory from ape_agent;
revoke update on ape.memory from ape_agent;
grant update (salience, last_used_at, embedding) on ape.memory to ape_agent;

-- ---------------------------------------------------------------------
-- Puntuación, búsqueda y olvido activo
-- score = salience * 0.5 ^ (días desde la última vez que se usó / vida media)
-- ---------------------------------------------------------------------
create or replace function ape.memory_score(p_salience real, p_created timestamptz,
                                            p_used timestamptz, p_half real)
returns double precision
language sql stable
set search_path = pg_catalog as $$
  select p_salience * power(0.5,
    extract(epoch from (now() - greatest(p_created, coalesce(p_used, p_created))))
      / 86400.0 / greatest(p_half, 0.1))
$$;

create or replace function ape.memory_search(p_query extensions.vector,
                                             p_max_class smallint,
                                             p_k integer default 5)
returns table (id uuid, kind text, content text, sensitivity smallint,
               external boolean, distance double precision)
language sql stable
set search_path = ape, extensions, public, pg_catalog as $$
  select m.id, m.kind, m.content, m.sensitivity, m.external,
         (m.embedding <=> p_query)::double precision
    from ape.memory m
   where m.sensitivity <= p_max_class and m.embedding is not null
   order by m.embedding <=> p_query
   limit p_k
$$;

-- Si hay más recuerdos que el máximo, conserva los mejores hasta el 90 % del máximo.
-- Los recuerdos fijados (pinned) nunca se olvidan.
create or replace function ape.memory_forget() returns integer
language plpgsql security definer
set search_path = ape, extensions, public, pg_catalog as $$
declare maxrows int; half real; total int; pinned_n int; keep int; n int := 0;
begin
  select (value #>> '{}')::int  into maxrows from ape.core_policy where key = 'memory_max_rows';
  select (value #>> '{}')::real into half    from ape.core_policy where key = 'memory_half_life_days';
  select count(*), count(*) filter (where pinned) into total, pinned_n from ape.memory;
  if total <= maxrows then return 0; end if;
  keep := greatest((maxrows * 9) / 10 - pinned_n, 0);
  with ranked as (
    select id, row_number() over (
             order by ape.memory_score(salience, created_at, last_used_at, half) desc) as rn
      from ape.memory where not pinned)
  delete from ape.memory m using ranked r where m.id = r.id and r.rn > keep;
  get diagnostics n = row_count;
  if n > 0 then
    perform ape._audit('memory.forget', jsonb_build_object('deleted', n, 'kept', keep + pinned_n));
  end if;
  return n;
end $$;

-- ---------------------------------------------------------------------
-- Bandeja de entrada: canal de Dani hacia el agente (y de fuentes externas).
-- from_dani lo fija la BD: escribe el agente/ejecutor => contenido externo.
-- ---------------------------------------------------------------------
create table if not exists ape.inbox (
  id           uuid primary key default gen_random_uuid(),
  source       text not null,
  content      text not null,
  from_dani    boolean not null default false,
  created_at   timestamptz not null default now(),
  processed_at timestamptz
);

create or replace function ape.inbox_guard() returns trigger
language plpgsql
set search_path = ape, extensions, public, pg_catalog as $$
begin
  new.from_dani := session_user not in ('ape_agent', 'ape_executor');
  new.processed_at := null;
  return new;
end $$;

drop trigger if exists inbox_guard on ape.inbox;
create trigger inbox_guard before insert on ape.inbox
  for each row execute function ape.inbox_guard();

-- (sin trigger de auditoría: el contenido puede ser sensible; el ciclo audita solo ids)

-- ---------------------------------------------------------------------
-- Permisos
-- ---------------------------------------------------------------------
revoke all on table ape.inbox from public;
grant select, insert on ape.inbox to ape_agent;
grant update (processed_at) on ape.inbox to ape_agent;

revoke all on function ape.memory_score(real, timestamptz, timestamptz, real) from public;
revoke all on function ape.memory_search(extensions.vector, smallint, integer) from public;
revoke all on function ape.memory_forget() from public;
grant execute on function ape.memory_score(real, timestamptz, timestamptz, real) to ape_agent;
grant execute on function ape.memory_search(extensions.vector, smallint, integer) to ape_agent, ape_executor;
grant execute on function ape.memory_forget() to ape_agent;
