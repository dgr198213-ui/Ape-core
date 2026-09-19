'use strict';
// Todo el contenido que llega del servidor se pinta con nodos de texto (nunca HTML crudo):
// lo que propone el agente puede venir de terceros.

const root = document.getElementById('app');
const S = { csrf: null, state: null, tab: 'resumen', status: null, pending: [], audit: [],
            toast: null, setup: null, confirming: null, busy: false };
let toastTimer = null;

function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== false && v !== null && v !== undefined) n.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

async function api(path, method, body) {
  const opt = { method: method || 'GET', credentials: 'same-origin', headers: {} };
  if (body !== undefined) { opt.body = JSON.stringify(body); opt.headers['Content-Type'] = 'application/json'; }
  if (S.csrf) opt.headers['X-CSRF'] = S.csrf;
  const r = await fetch(path, opt);
  let data = {};
  try { data = await r.json(); } catch (_) { /* sin cuerpo */ }
  if (r.status === 401 && S.state && S.state.authenticated) { S.state.authenticated = false; S.csrf = null; render(); }
  if (!r.ok) throw new Error(data.error || ('Error ' + r.status));
  return data;
}

function flash(text, kind) {
  S.toast = { text, kind: kind || 'ok' };
  render();
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { S.toast = null; const t = root.querySelector('.toast'); if (t) t.remove(); }, 4500);
}

async function run(fn) {
  if (S.busy) return;
  S.busy = true;
  try { await fn(); } catch (e) { flash(e.message, 'bad'); } finally { S.busy = false; render(); }
}

async function loadState() {
  S.state = await api('/api/state');
  S.csrf = S.state.csrf;
}

async function refresh() {
  if (!S.state || !S.state.authenticated) return;
  try {
    S.status = await api('/api/status');
    S.pending = await api('/api/pending');
    if (S.tab === 'historial') S.audit = await api('/api/audit');
  } catch (e) { flash(e.message, 'bad'); }
  render();
}

// ---------------------------------------------------------------- pantallas

function fieldset(label, input) { return el('label', {}, el('div', { class: 'dim' }, label), input); }

function setupScreen() {
  if (!S.setup) {
    const token = el('input', { type: 'password', autocomplete: 'off', placeholder: 'Código de configuración' });
    return el('div', { class: 'center' },
      el('h1', {}, 'Configurar el panel'),
      el('p', { class: 'dim' }, 'Primera vez: introduce el código de configuración que definiste en Vercel.'),
      token,
      el('button', { onclick: () => run(async () => {
        const r = await api('/api/setup/start', 'POST', { setup_token: token.value });
        S.setup = { token: token.value, secret: r.totp_secret, otpauth: r.otpauth };
      }) }, 'Continuar'));
  }
  const pass = el('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Frase de paso (mín. 12)' });
  const code = el('input', { inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: 'Código de 6 dígitos' });
  return el('div', { class: 'center' },
    el('h1', {}, 'Tu app de autenticación'),
    el('p', {}, 'Añade esta clave en tu app de autenticación (Google Authenticator, Authy, 2FAS…):'),
    el('pre', {}, S.setup.secret),
    el('a', { href: S.setup.otpauth }, 'Abrir en mi app de autenticación'),
    fieldset('Elige tu frase de paso', pass),
    fieldset('Código que muestra la app', code),
    el('button', { onclick: () => run(async () => {
      await api('/api/setup/finish', 'POST', { setup_token: S.setup.token, passphrase: pass.value,
                                               totp_secret: S.setup.secret, code: code.value });
      S.setup = null;
      await loadState();
      flash('Panel configurado. Ya puedes entrar.');
    }) }, 'Terminar'));
}

function loginScreen() {
  const pass = el('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Frase de paso' });
  const code = el('input', { inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: 'Código de 6 dígitos' });
  return el('div', { class: 'center' },
    el('h1', {}, 'APE'),
    pass, code,
    el('button', { onclick: () => run(async () => {
      await api('/api/login', 'POST', { passphrase: pass.value, code: code.value });
      await loadState();
      await refresh();
    }) }, 'Entrar'));
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' });
}

function resumenTab() {
  const s = S.status;
  if (!s) return el('p', { class: 'dim' }, 'Cargando…');
  const lc = s.last_cycle;
  const cards = [];
  cards.push(el('div', { class: 'card' },
    el('h2', {}, 'Estado del agente'),
    el('div', { class: 'big ' + (s.kill.active ? 'bad' : 'ok') }, s.kill.active ? 'PARADO' : 'Activo'),
    s.kill.active ? el('div', { class: 'dim' }, 'Motivo: ' + (s.kill.reason || '—')) : null,
    s.kill.active ? (() => {
      const code = el('input', { inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: 'Código nuevo de la app' });
      return el('div', { class: 'row' }, code, el('button', { class: 'sec', onclick: () => run(async () => {
        await api('/api/resume', 'POST', { code: code.value }); flash('Reanudado.'); await refresh();
      }) }, 'Reanudar'));
    })() : null));
  cards.push(el('div', { class: 'card' },
    el('h2', {}, 'Esperan tu aprobación'),
    el('div', { class: 'big ' + (s.pending_approval ? 'warn' : '') }, s.pending_approval),
    el('div', { class: 'dim' }, s.other_proposals + ' propuestas menores · ' + s.inbox_waiting + ' mensajes en cola')));
  cards.push(el('div', { class: 'card' },
    el('h2', {}, 'Último ciclo'),
    lc ? el('div', {}, fmtTime(lc.at)) : el('div', { class: 'dim' }, 'Aún no se ha ejecutado ningún ciclo.'),
    lc ? el('div', { class: 'dim' }, lc.events + ' entradas · ' + lc.proposals + ' propuestas · ' + lc.denied +
      ' denegadas · ' + lc.withheld + ' retenidas' + ((lc.errors || []).length ? ' · incidencias: ' + lc.errors.join(', ') : '')) : null,
    S.state.can_run_cycle ? el('button', { class: 'sec', onclick: () => run(async () => {
      await api('/api/run-cycle', 'POST', {}); flash('Ciclo lanzado. Tardará un par de minutos.');
    }) }, 'Ejecutar ciclo ahora') : null));
  cards.push(el('div', { class: 'card' },
    el('h2', {}, 'Auditoría'),
    el('div', { class: s.audit_ok ? 'ok' : 'bad' }, s.audit_ok ? 'Cadena íntegra' : 'CADENA ROTA en #' + s.audit_broken_at),
    el('div', { class: 'dim' }, 'Cabeza: ' + (s.audit_head ? s.audit_head.slice(0, 16) + '…' : '—'))));
  return cards;
}

function hablarTab() {
  const t = el('textarea', { placeholder: 'Dile algo al agente. Lo leerá en su próximo ciclo.' });
  return el('div', { class: 'card' }, el('h2', {}, 'Mensaje para el agente'), t,
    el('button', { onclick: () => run(async () => {
      await api('/api/say', 'POST', { text: t.value }); t.value = ''; flash('Enviado.'); await refresh();
    }) }, 'Enviar'));
}

function pendientesTab() {
  if (!S.pending.length) return el('p', { class: 'dim' }, 'Nada pendiente de tu aprobación.');
  return S.pending.map((p) => {
    const external = p.origin === 'external_content';
    const confirming = S.confirming === p.id;
    const code = el('input', { inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: 'Código nuevo de la app' });
    return el('div', { class: 'card' },
      el('h2', {}, p.tool + ' · N' + p.level),
      el('div', { class: 'big' }, p.cost_eur + ' €'),
      external ? el('div', { class: 'warn' }, '⚠ Derivada de contenido externo (posible manipulación). Revísala con cuidado.') : null,
      !p.hash_ok ? el('div', { class: 'bad' }, '⚠ El hash no coincide con los argumentos. No se puede aprobar.') : null,
      el('pre', {}, JSON.stringify(p.args, null, 2)),
      confirming ? el('div', { class: 'row' }, code, el('button', { onclick: () => run(async () => {
        await api('/api/approve', 'POST', { id: p.id, code: code.value });
        S.confirming = null; flash('Aprobada. El ejecutor la usará si sigue vigente.'); await refresh();
      }) }, 'Confirmar')) : null,
      el('div', { class: 'row' },
        !confirming ? el('button', { disabled: !p.hash_ok, onclick: () => { S.confirming = p.id; render(); } }, 'Aprobar') : null,
        el('button', { class: 'sec', onclick: () => { if (confirm('¿Rechazar esta acción?')) run(async () => {
          await api('/api/reject', 'POST', { id: p.id }); S.confirming = null; flash('Rechazada.'); await refresh();
        }); } }, 'Rechazar')));
  });
}

function historialTab() {
  if (!S.audit.length) return el('p', { class: 'dim' }, 'Cargando…');
  return el('div', { class: 'card' }, el('h2', {}, 'Últimos eventos'),
    el('ul', { style: 'margin:0;padding-left:18px' },
      S.audit.map((e) => el('li', {}, el('span', { class: 'dim' }, fmtTime(e.at) + ' '), e.type,
                            el('span', { class: 'dim' }, ' (' + e.role + ')')))));
}

function mainScreen() {
  const s = S.status;
  const tabs = [['resumen', 'Resumen'], ['hablar', 'Hablar'], ['pendientes', 'Pendientes'], ['historial', 'Historial']];
  const body = { resumen: resumenTab, hablar: hablarTab, pendientes: pendientesTab, historial: historialTab }[S.tab]();
  return [
    el('header', {},
      el('h1', {}, 'APE'),
      el('span', { class: 'pill ' + (s && s.kill.active ? 'bad' : 'ok') }, s && s.kill.active ? 'Parado' : 'Activo'),
      el('button', { class: 'danger', 'aria-label': 'Parar el agente', onclick: () => {
        if (confirm('¿PARAR el agente ahora? Ningún ciclo actuará hasta que lo reanudes.')) run(async () => {
          await api('/api/kill', 'POST', { reason: 'desde el panel' }); flash('PARADO.', 'bad'); await refresh();
        });
      } }, 'PARAR')),
    el('main', {}, body),
    el('nav', {}, tabs.map(([id, label]) => el('button', {
      class: S.tab === id ? 'on' : '', onclick: () => { S.tab = id; S.confirming = null; render(); refresh(); } },
      label, id === 'pendientes' && s && s.pending_approval ? el('span', { class: 'badge' }, s.pending_approval) : null))),
    el('div', { class: 'card', style: 'margin:0 12px 12px' },
      el('button', { class: 'sec', onclick: () => run(async () => { await api('/api/logout', 'POST', {}); await loadState(); }) }, 'Cerrar sesión')),
  ];
}

function render() {
  const active = document.activeElement;
  const keep = active && active.tagName === 'TEXTAREA' && active.value ? active.value : null;
  root.replaceChildren();
  if (!S.state) root.append(el('p', { class: 'center dim' }, 'Cargando…'));
  else if (S.state.setup_needed) root.append(setupScreen());
  else if (!S.state.authenticated) root.append(loginScreen());
  else root.append(...mainScreen());
  if (S.toast) root.append(el('div', { class: 'toast ' + S.toast.kind }, S.toast.text));
  if (keep !== null) { const t = root.querySelector('textarea'); if (t) t.value = keep; }
}

(async function start() {
  render();
  try { await loadState(); await refresh(); } catch (e) { flash(e.message, 'bad'); }
  render();
  setInterval(() => {
    const a = document.activeElement;
    const typing = a && (a.tagName === 'INPUT' || a.tagName === 'TEXTAREA');
    if (!document.hidden && !typing && S.state && S.state.authenticated && !S.busy) refresh();
  }, 30000);
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
})();
