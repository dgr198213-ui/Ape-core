-- Endurecimiento derivado de los avisos de seguridad de Supabase (19-sep-2026):
--  * pgvector fuera del esquema public
--  * search_path fijo en todas las funciones del esquema ape
-- Idempotente: sirve tanto para instalaciones nuevas como para la ya desplegada.

create schema if not exists extensions;
-- Los roles de la aplicación necesitan USAGE para resolver el tipo vector.
grant usage on schema extensions to ape_agent, ape_executor;

do $$
begin
  if (select n.nspname from pg_extension e join pg_namespace n on n.oid = e.extnamespace
       where e.extname = 'vector') <> 'extensions' then
    alter extension vector set schema extensions;
  end if;
end $$;

alter function ape.deny_mutation()        set search_path = ape, extensions, public, pg_catalog;
alter function ape.strategy_guard()       set search_path = ape, extensions, public, pg_catalog;
alter function ape.action_before_insert() set search_path = ape, extensions, public, pg_catalog;

alter role ape_agent    set search_path = ape, extensions, public, pg_catalog;
alter role ape_executor set search_path = ape, extensions, public, pg_catalog;
