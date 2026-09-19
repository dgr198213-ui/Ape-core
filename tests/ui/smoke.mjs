// Prueba de humo de la interfaz: carga index.html + app.js en jsdom contra el servidor real.
import { JSDOM, VirtualConsole } from 'jsdom';

const [base, sessionToken, approveCode] = process.argv.slice(2);
const jar = new Map([['__Host-ape_session', sessionToken]]);

async function jfetch(path, opts = {}) {
  const url = new URL(path, base);
  const headers = { ...(opts.headers || {}), cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
                    origin: new URL(base).origin };
  const r = await fetch(url, { ...opts, headers, redirect: 'manual' });
  for (const sc of r.headers.getSetCookie()) {
    const pair = sc.split(';')[0]; const i = pair.indexOf('=');
    const k = pair.slice(0, i).trim(), v = pair.slice(i + 1);
    if (/max-age=0/i.test(sc) || /expires=thu, 01 jan 1970/i.test(sc) || v === '') jar.delete(k); else jar.set(k, v);
  }
  return r;
}

const html = await (await fetch(base + '/')).text();
const vc = new VirtualConsole();
vc.on('jsdomError', (e) => console.log('JSDOM-ERROR:', e.message, (e.detail && e.detail.stack || '').split('\n').slice(0, 4).join(' | ')));
vc.on('error', (...a) => console.log('CONSOLE-ERROR:', ...a));
const dom = new JSDOM(html, { url: base + '/', runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc });
const w = dom.window;
w.fetch = (p, o) => jfetch(typeof p === 'string' ? p : p.url, o);
w.confirm = () => true;
const errors = [];
w.addEventListener('error', (e) => errors.push(String(e.message)));
w.eval(await (await fetch(base + '/app.js')).text());

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const $ = (s) => w.document.querySelector(s);
const $$ = (s) => [...w.document.querySelectorAll(s)];
const btn = (text) => $$('button').find((b) => b.textContent.trim().startsWith(text));
const toast = () => ($('.toast') || {}).textContent || '';
async function waitFor(fn, label, timeout = 6000) {
  const t0 = Date.now();
  for (;;) {
    try { const v = fn(); if (v) return v; } catch (_) { /* reintenta */ }
    if (Date.now() - t0 > timeout) throw new Error('timeout esperando: ' + label + ' | pantalla: ' + w.document.body.innerHTML.slice(0, 700));
    await sleep(25);
  }
}
const type = (el, value) => { el.value = value; el.dispatchEvent(new w.Event('input', { bubbles: true })); };
const idle = () => sleep(600);   // deja terminar las actualizaciones en curso (un humano tarda más)
const step = (msg) => console.log('  ok · ' + msg);

// 1. Resumen
await waitFor(() => ($('.big.ok') || {}).textContent === 'Activo', 'estado Activo');
step('resumen con agente activo');

// 2. Hablar
btn('Hablar').click();
const ta = await waitFor(() => $('textarea'), 'cuadro de mensaje');
type(ta, 'hola desde la prueba');
btn('Enviar').click();
await waitFor(() => toast().startsWith('Enviado'), 'aviso Enviado');
await idle();
step('mensaje enviado');

// 3. Pendientes: el contenido del agente se pinta como texto, nunca como HTML
btn('Pendientes').click();
await waitFor(() => $$('.card h2').some((h) => h.textContent.startsWith('payment.execute')), 'tarjeta pendiente');
const pre = $('pre');
if (!pre.textContent.includes('<img src=x')) throw new Error('el contenido no se muestra literal');
if ($$('img').length !== 0) throw new Error('se inyectó un elemento <img>');
if (w.__pwned) throw new Error('se ejecutó código inyectado');
if (!$$('.warn').some((n) => n.textContent.includes('contenido externo'))) throw new Error('falta el aviso de origen externo');
step('pendiente mostrada como texto, con aviso de origen externo');

// 4. Aprobar con código nuevo
btn('Aprobar').click();
const codeInput = await waitFor(() => $$('input').find((i) => i.placeholder.startsWith('Código nuevo')), 'campo de código');
type(codeInput, approveCode);
btn('Confirmar').click();
await waitFor(() => toast().startsWith('Aprobada'), 'aviso Aprobada');
await waitFor(() => w.document.body.textContent.includes('Nada pendiente de tu aprobación'), 'lista vacía');
step('aprobación con código de un solo uso');
await idle();

// 5. Parar
btn('PARAR').click();
await waitFor(() => toast().startsWith('PARADO'), 'aviso PARADO');
btn('Resumen').click();
await waitFor(() => ($('.big.bad') || {}).textContent === 'PARADO', 'estado PARADO');
await waitFor(() => $('header .pill').textContent === 'Parado', 'pastilla Parado');
step('parada inmediata');
await idle();

// 6. Cerrar sesión y credenciales incorrectas
btn('Cerrar sesión').click();
const pass = await waitFor(() => $('input[type=password]'), 'pantalla de acceso');
if ($('nav')) throw new Error('la navegación sigue visible tras cerrar sesión');
type(pass, 'una frase incorrecta!!');
type($$('input').find((i) => i.placeholder.startsWith('Código')), '000000');
btn('Entrar').click();
await waitFor(() => toast().includes('credenciales incorrectas'), 'aviso de credenciales');
step('acceso rechazado con credenciales incorrectas');

if (errors.length) throw new Error('errores de JavaScript: ' + errors.join(' | '));
console.log('UI OK');
w.close();
process.exit(0);
