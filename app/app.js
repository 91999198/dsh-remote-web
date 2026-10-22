/**
 * app.js — UI wiring.
 *
 * Layout mirrors the Desktop Harness: a session sidebar on the left (grouped by
 * workspace, archived conversations filtered out), a conversation column, and a
 * composer pinned to the bottom. The palette is the Desktop dark theme's.
 *
 * Rendering contract: history items reuse the live ev.message_delta / ev.tool_event
 * shapes (see @dsh-remote/protocol/wire/payloads.js), so one renderer serves both.
 */
import { RemoteClient, stripPairingToken } from './client.js';

const $ = (id) => document.getElementById(id);
const el = {
  status: $('status'),
  pairPanel: $('pairPanel'),
  pairError: $('pairError'),
  uri: $('uri'),
  connect: $('connect'),
  dismiss: $('dismiss'),
  forget: $('forget'),
  sessions: $('sessions'),
  feed: $('feed'),
  feedInner: $('feedInner'),
  composer: $('composer'),
  prompt: $('prompt'),
  send: $('send'),
  toggleLogs: $('toggleLogs'),
  refresh: $('refresh'),
  interrupt: $('interrupt'),
  logs: $('logs'),
  sessionTitle: $('sessionTitle'),
  sessionMeta: $('sessionMeta'),
  openSidebar: $('openSidebar'),
  closeSidebar: $('closeSidebar'),
  scrim: $('scrim'),
};

const STORE_KEY = 'dsh-remote-uri';        // pairing URI (one-time code stripped after pairing)
const SESSION_KEY = 'dsh-remote-session';  // { convId, hostId, clientId } — lets a reload resume

function loadSession() {
  try { return JSON.parse(localStorage.getItem(SESSION_KEY) ?? 'null'); } catch { return null; }
}
function saveSession(s) {
  try { localStorage.setItem(SESSION_KEY, JSON.stringify(s)); } catch { /* private mode */ }
}
function clearSession() {
  try { localStorage.removeItem(SESSION_KEY); } catch {}
}

// Hard environment requirements, checked before anything else.
const envProblems = [];
if (!globalThis.nacl?.secretbox) {
  envProblems.push('tweetnacl 未加载（vendor/nacl-fast.js 没被引入）');
}
if (!globalThis.crypto?.subtle) {
  envProblems.push('WebCrypto 不可用 —— 此页面必须通过 HTTPS 或 http://localhost 打开');
}

const state = {
  client: null,
  sessions: [],
  currentSessionId: null,
  messages: new Map(),
  tools: new Map(),
  cards: new Map(),
  latestSeq: new Map(),
  running: false,
};

// ── helpers ──────────────────────────────────────────────────────────
function mk(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setStatus(text, tone = 'warn') {
  el.status.textContent = text;
  el.status.dataset.tone = tone;
}

function log(line, level = 'info') {
  const row = mk('div', null, new Date().toLocaleTimeString() + '  ' + line);
  row.dataset.level = level;
  el.logs.appendChild(row);
  el.logs.scrollTop = el.logs.scrollHeight;
  while (el.logs.childElementCount > 400) el.logs.firstElementChild.remove();
}

function atBottom() {
  return el.feed.scrollHeight - el.feed.scrollTop - el.feed.clientHeight < 80;
}
function scrollIfSticky(sticky) {
  if (sticky) el.feed.scrollTop = el.feed.scrollHeight;
}

/** "3 分钟前" style, falling back to a date for old rows. */
function relativeTime(iso) {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const sec = Math.round((Date.now() - t) / 1000);
  if (sec < 60) return '刚刚';
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时前`;
  if (sec < 86400 * 7) return `${Math.floor(sec / 86400)} 天前`;
  const d = new Date(t);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

/** Last path segment of a workspace path, for the group heading. */
function workspaceLabel(path) {
  const p = String(path ?? '').replace(/[\\/]+$/, '');
  if (!p) return '未分组';
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : p;
}

/** Only live conversations, like the desktop list: no archived, no subagent rows. */
function visibleSessions() {
  return state.sessions
    .filter((s) => s.state !== 'archived' && s.origin !== 'subagent')
    .sort((a, b) => String(b.updatedAt ?? '').localeCompare(String(a.updatedAt ?? '')));
}

// ── session list ─────────────────────────────────────────────────────
function renderSessions() {
  el.sessions.replaceChildren();
  const rows = visibleSessions();
  if (!rows.length) {
    el.sessions.appendChild(mk('div', 'group-title', '没有可显示的会话'));
    return;
  }

  // Group by workspace, the way the desktop sidebar does.
  const groups = new Map();
  for (const s of rows) {
    const key = s.workspace ?? '';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(s);
  }

  for (const [workspace, list] of groups) {
    const group = mk('div', 'group');
    const head = mk('div', 'group-title');
    head.append(mk('span', null, workspaceLabel(workspace)), mk('span', null, String(list.length)));
    group.appendChild(head);

    for (const s of list) {
      const row = mk('button', 'sess');
      row.type = 'button';
      row.setAttribute('aria-current', String(s.id === state.currentSessionId));

      const dot = mk('span', 'dot');
      dot.dataset.tone =
        s.running || s.state === 'running' ? 'running'
        : s.state === 'awaiting-permission' || s.state === 'awaiting-answer' ? 'asking'
        : 'idle';

      const body = mk('span', 'body');
      body.appendChild(mk('div', 't', s.title || s.id.slice(0, 18)));
      body.appendChild(mk('div', 'when', relativeTime(s.updatedAt)));

      row.append(dot, body);
      row.onclick = () => { selectSession(s.id); closeDrawer(); };
      group.appendChild(row);
    }
    el.sessions.appendChild(group);
  }
}

function currentSummary() {
  return state.sessions.find((s) => s.id === state.currentSessionId) ?? null;
}

function selectSession(sessionId) {
  if (state.currentSessionId === sessionId) return;
  state.currentSessionId = sessionId;
  state.messages.clear();
  state.tools.clear();
  state.cards.clear();
  el.feedInner.replaceChildren();
  el.composer.hidden = false;
  const s = currentSummary();
  el.sessionTitle.textContent = s?.title || sessionId.slice(0, 18);
  el.sessionMeta.textContent = [workspaceLabel(s?.workspace), relativeTime(s?.updatedAt)].filter(Boolean).join(' · ');
  renderSessions();
  log('打开会话 ' + sessionId);
  state.client.history(sessionId, { limit: 60 });
  state.client.getPending(sessionId);
}

// ── feed ─────────────────────────────────────────────────────────────
function appendNote(text, tone) {
  const row = mk('div', 'note', text);
  if (tone) row.dataset.tone = tone;
  el.feedInner.appendChild(row);
}

function renderDelta(p) {
  const sticky = atBottom();
  if (p.sessionId && p.sessionId !== state.currentSessionId) return;
  if (!p.messageId) return;

  let node = state.messages.get(p.messageId);
  if (!node) {
    const turn = mk('div', 'turn ' + (p.role === 'user' ? 'user' : 'assistant'));
    turn.appendChild(mk('div', 'bubble'));
    el.feedInner.appendChild(turn);
    state.messages.set(p.messageId, turn);
    node = turn;
  }
  const bubble = node.querySelector('.bubble');
  if (typeof p.delta === 'string' && p.delta.length) bubble.textContent += p.delta;
  scrollIfSticky(sticky);
}

function renderTool(p) {
  const sticky = atBottom();
  if (p.sessionId && p.sessionId !== state.currentSessionId) return;
  const key = p.callId || 'anon';
  let node = state.tools.get(key);
  if (!node) {
    node = mk('div', 'tool');
    el.feedInner.appendChild(node);
    state.tools.set(key, node);
  }
  node.dataset.phase = p.phase;
  const bits = [`[${p.phase}]`];
  if (p.tool) bits.push(p.tool);
  if (p.title) bits.push('— ' + p.title);
  if (p.argsPreview) bits.push('\n' + p.argsPreview);
  if (p.resultPreview && (p.phase === 'completed' || p.phase === 'failed')) bits.push('\n' + p.resultPreview);
  node.textContent = bits.join(' ');
  scrollIfSticky(sticky);
}

function renderPermission(p) {
  if (state.cards.has(p.requestId)) return;
  const card = mk('div', 'card');
  card.appendChild(mk('h3', null, '需要审批：' + p.action));
  if (p.resource) card.appendChild(mk('p', null, p.resource));
  if (p.reason) card.appendChild(mk('p', null, p.reason));
  const opts = mk('div', 'opts');
  for (const o of p.options ?? [{ id: 'approve', label: '允许' }, { id: 'reject', label: '拒绝' }]) {
    const b = mk('button', o.id === 'reject' ? '' : 'sel', o.label);
    b.onclick = () => {
      state.client.resolvePermission(p.sessionId ?? state.currentSessionId, p.requestId, o.id);
      card.remove();
      state.cards.delete(p.requestId);
    };
    opts.appendChild(b);
  }
  card.appendChild(opts);
  el.feedInner.appendChild(card);
  state.cards.set(p.requestId, card);
  scrollIfSticky(true);
}

function renderQuestion(p) {
  if (state.cards.has(p.requestId)) return;
  const card = mk('div', 'card question');
  card.appendChild(mk('h3', null, 'Coo 有问题要问你'));
  const inputs = [];
  for (const q of p.questions ?? []) {
    card.appendChild(mk('p', null, q.question));
    if (Array.isArray(q.options) && q.options.length) {
      const opts = mk('div', 'opts');
      const chosen = new Set();
      for (const o of q.options) {
        const b = mk('button', null, o.label);
        b.onclick = () => {
          if (q.multi) {
            if (chosen.has(o.id)) { chosen.delete(o.id); b.classList.remove('sel'); }
            else { chosen.add(o.id); b.classList.add('sel'); }
          } else {
            for (const sib of opts.children) sib.classList.remove('sel');
            chosen.clear();
            chosen.add(o.id);
            b.classList.add('sel');
          }
        };
        opts.appendChild(b);
      }
      card.appendChild(opts);
      inputs.push({ q, chosen });
    } else {
      const input = document.createElement('input');
      input.type = 'text';
      input.placeholder = '回答…';
      card.appendChild(input);
      inputs.push({ q, input, chosen: new Set() });
    }
  }
  const submit = mk('button', 'sel', '提交');
  submit.onclick = () => {
    const answers = inputs.map(({ q, input, chosen }) => ({
      questionId: q.id,
      selected: [...chosen],
      ...(input && input.value ? { freeText: input.value } : {}),
    })).filter((a) => a.selected.length || a.freeText);
    if (!answers.length) return;
    state.client.answer(p.sessionId ?? state.currentSessionId, p.requestId, answers);
    card.remove();
    state.cards.delete(p.requestId);
  };
  const wrap = mk('div', 'opts');
  wrap.appendChild(submit);
  card.appendChild(wrap);
  el.feedInner.appendChild(card);
  state.cards.set(p.requestId, card);
  scrollIfSticky(true);
}

function dropCard(requestId) {
  const card = state.cards.get(requestId);
  if (card) { card.remove(); state.cards.delete(requestId); }
}

// ── payload dispatch ─────────────────────────────────────────────────
function handlePayload(p) {
  if (!p || typeof p.t !== 'string') return;
  switch (p.t) {
    case 'ev.session_changed': {
      state.sessions = p.sessions ?? [];
      const alive = visibleSessions().some((s) => s.id === state.currentSessionId);
      if (!state.currentSessionId || !alive) {
        const pick = visibleSessions().find((s) => s.running || s.state === 'running') ?? visibleSessions()[0];
        if (pick) selectSession(pick.id);
      }
      renderSessions();
      return;
    }
    case 'ev.session_history': {
      if (p.sessionId !== state.currentSessionId) return;
      const items = p.items ?? [];
      for (const item of items) handlePayload(item);
      if (typeof p.latestSeq === 'number') state.latestSeq.set(p.sessionId, p.latestSeq);
      appendNote(`载入 ${items.length} 条历史${p.nextBeforeSeq !== undefined ? '（还有更早的）' : ''}`);
      return;
    }
    case 'ev.message_delta':
      renderDelta(p);
      return;
    case 'ev.tool_event':
      renderTool(p);
      return;
    case 'ev.run_state': {
      const mine = !p.sessionId || p.sessionId === state.currentSessionId;
      state.running = p.state === 'running';
      if (mine) {
        setStatus(state.running ? '运行中' : '空闲', state.running ? 'ok' : 'warn');
        appendNote(p.detail ? `${p.state} · ${p.detail}` : p.state);
      }
      return;
    }
    case 'ev.permission_request': renderPermission(p); return;
    case 'ev.permission_resolved':
      dropCard(p.requestId);
      appendNote('审批已由' + (p.by === 'desktop' ? '桌面' : '撤回') + '处理');
      return;
    case 'ev.question_request': renderQuestion(p); return;
    case 'ev.question_resolved': dropCard(p.requestId); return;
    case 'ev.host_info':
      appendNote(`主机 ${p.host?.platform ?? '?'}/${p.host?.arch ?? '?'} · DSH ${p.host?.dshVersion ?? '?'}`);
      return;
    case 'ev.retry':
      appendNote(`模型重试 ${p.attempt}/${p.max}${p.reason ? ' · ' + p.reason : ''}`, 'warn');
      return;
    case 'ev.compaction':
      appendNote(`上下文压缩 ${p.state}${p.error ? ' · ' + p.error : ''}`, p.state === 'failed' ? 'err' : undefined);
      return;
    case 'ev.result':
      if (p.ok === false) appendNote('命令失败：' + (p.message ?? p.cmdId), 'err');
      else log('cmd ok ' + p.cmdId);
      return;
    case 'ev.todo':
    case 'ev.model':
    case 'ev.keep_awake_state':
      return;
    default:
      log('未处理的载荷：' + p.t, 'warn');
  }
}

// ── drawer (narrow screens) ──────────────────────────────────────────
function openDrawer() { document.body.classList.add('drawer-open'); }
function closeDrawer() { document.body.classList.remove('drawer-open'); }
el.openSidebar.onclick = openDrawer;
el.closeSidebar.onclick = closeDrawer;
el.scrim.onclick = closeDrawer;

// ── pairing overlay ──────────────────────────────────────────────────
function showPair(message) {
  el.pairPanel.hidden = false;
  if (message) { el.pairError.hidden = false; el.pairError.textContent = message; }
  else el.pairError.hidden = true;
}
function hidePair() {
  el.pairPanel.hidden = true;
  el.pairError.hidden = true;
}
el.dismiss.onclick = () => {
  el.pairPanel.hidden = true;
  if (!state.client) setStatus('未连接', 'warn');
};

// ── client ───────────────────────────────────────────────────────────
function makeClient() {
  return new RemoteClient({
    onPayload: handlePayload,
    onStatus: (s, detail) => {
      if (s === 'ready') setStatus('已连接', 'ok');
      else if (s === 'connecting' || s === 'open' || s === 'pairing' || s === 'deriving' || s === 'waiting-host') setStatus('连接中…', 'warn');
      else if (s === 'need-repair') { setStatus('需重新配对', 'err'); showPair(detail); }
      else if (s === 'pair-fail') { setStatus('配对失败', 'err'); showPair(detail); }
      else if (s === 'error') setStatus('出错', 'err');
      else if (s === 'closed') setStatus('已断开', 'err');
      else if (s === 'host-left') setStatus('主机离线', 'warn');
      else setStatus(s, 'warn');
      if (detail) log(`[${s}] ${detail}`);
    },
    onLog: log,
    onSession: (session) => {
      saveSession(session);
      const uri = el.uri.value.trim();
      if (/[?&]t=\d{6}/.test(uri)) {
        const stripped = stripPairingToken(uri);
        el.uri.value = stripped;
        try { localStorage.setItem(STORE_KEY, stripped); } catch {}
      }
    },
    onSessionLost: (reason) => {
      clearSession();
      log('需要重新配对：' + reason, 'error');
    },
  });
}

async function connect() {
  const uri = el.uri.value.trim();
  if (!uri) { showPair('请先粘贴配对 URI'); return; }
  const stored = loadSession();
  const hasToken = /[?&]t=\d{6}/.test(uri);
  if (hasToken) clearSession();
  try { localStorage.setItem(STORE_KEY, uri); } catch {}
  state.client?.stop();
  state.client = makeClient();
  state.currentSessionId = null;
  state.messages.clear();
  state.tools.clear();
  el.feedInner.replaceChildren();
  el.sessionTitle.textContent = '未选择会话';
  el.sessionMeta.textContent = '连接后从会话列表里选一个';
  el.composer.hidden = true;
  try {
    await state.client.start(uri, hasToken ? null : stored);
    hidePair();
  } catch (e) {
    setStatus('连接失败', 'err');
    log('连接失败：' + e.message, 'error');
    showPair('连接失败：' + e.message);
  }
}

el.connect.onclick = connect;
el.forget.onclick = () => {
  clearSession();
  try { localStorage.removeItem(STORE_KEY); } catch {}
  el.uri.value = '';
  state.client?.stop();
  state.client = null;
  el.sessions.replaceChildren();
  el.feedInner.replaceChildren();
  el.composer.hidden = true;
  setStatus('已清除', 'warn');
  showPair();
};

// ── composer / toolbar ───────────────────────────────────────────────
el.send.onclick = () => {
  const text = el.prompt.value.trim();
  if (!text) return;
  if (!state.currentSessionId) { log('还没有选定会话', 'warn'); return; }
  if (state.client.sendPrompt(state.currentSessionId, text)) {
    el.prompt.value = '';
    el.prompt.style.height = 'auto';
  }
};
el.prompt.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); el.send.click(); }
});
el.prompt.addEventListener('input', () => {
  el.prompt.style.height = 'auto';
  el.prompt.style.height = Math.min(el.prompt.scrollHeight, window.innerHeight * 0.3) + 'px';
});
el.refresh.onclick = () => state.client?.listSessions();
el.interrupt.onclick = () => { if (state.currentSessionId) state.client?.interrupt(state.currentSessionId); };
el.toggleLogs.onclick = () => { el.logs.hidden = !el.logs.hidden; };

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') state.client?.ensureConnected();
});
window.addEventListener('focus', () => state.client?.ensureConnected());
window.addEventListener('online', () => state.client?.ensureConnected());

// ── boot ─────────────────────────────────────────────────────────────
if (envProblems.length) {
  setStatus('环境不满足', 'err');
  for (const problem of envProblems) log(problem, 'error');
  el.connect.disabled = true;
  showPair(envProblems.join('；'));
} else {
  const saved = localStorage.getItem(STORE_KEY);
  if (saved) {
    el.uri.value = saved;
    const session = loadSession();
    log(session ? `已保存通道 ${session.convId}，直接续连（无需重新配对）` : '已载入上次的配对 URI');
    connect();
  } else {
    setStatus('未连接', 'warn');
    showPair();
    log('粘贴配对 URI 后点「连接并配对」');
  }
}
