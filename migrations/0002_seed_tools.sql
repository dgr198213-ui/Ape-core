-- Herramientas iniciales. Solo el propietario puede modificar este registro.
insert into ape.tool_spec(name, level, involves_money, reversible) values
  ('memory.search',   0, false, true),
  ('web.research',    0, false, true),
  ('draft.write',     0, false, true),
  ('memory.write',    1, false, true),
  ('notify.dani',     1, false, true),
  ('message.send',    2, false, false),
  ('account.signup',  2, false, false),
  ('contract.sign',   3, false, false),
  ('payment.execute', 3, true,  false)
on conflict (name) do nothing;
