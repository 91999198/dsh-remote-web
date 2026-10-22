/**
 * app.js — UI wiring for the DSH remote-control web client.
 * Rendering rules follow @dsh-remote/protocol/wire/payloads.js: history items reuse
 * the live ev.message_delta / ev.tool_event shapes, so one renderer serves both.
 */
import { RemoteClient } from './client.js';

const $ = (id) => document.getElementById(id);
const el = {
  status: $('status'),
  pairPanel: $('pairPanel'),
  uri: $('uri'),
  connect: $('connect'),
  forget: $('forget'),
  sessions: $('sessions'),
  feed: $('feed'),
  composer: $('composer'),
  prompt: $('prompt'),
  send: $('send'),
  toggleLogs: $('toggleLogs'),
  refresh: $('refresh'),
  interrupt: $('interrupt'),
  logs: $('logs'),
};

const STORE_KEY = 'dsh-remote-uri';

// Hard environment requirements, checked before anything else.
const envProblems = [];
if (!globalThis.nacl?.secretbox) {
  envProblems.push('tweetnacl 未加载（vendor/nacl-fast.js 没被引入）');
}
if (!globalThis.crypto?.subtle) {
  envProblems.push('WebCrypto 不可用 —— 此页面必须通过 HTTPS 或 http://localhost 打开（明文 http + IP 地址不是安全上下文）');
}

const state = {
  client: null,
  sessions: [],
  currentSessionId: null,
  messages: new Map(),   // messageId -> element
  tools: new Map(),      // callId -> element
  cards: new Map(),      // requestId -> element
  latestSeq: new Map(),  // dsh sessionId -> last seen seq (for resume)
  running: false,
};

// ── small helpers ────────────────────────────────────────────────────
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
  return el.feed.scrollHeight - el.feed.scrollTop - el.feed.clientHeight < 60;
}
function scrollIfSticky(sticky) {
  if (sticky) el.feed.scrollTop = el.feed.scrollHeight;
}

// ── session list ─────────────────────────────────────────────────────
function renderSessions() {
  el.sessions.replaceChildren();
  if (!state.sessions.length) {
    el.sessions.hidden = true;
    return;
  }
  el.sessions.hidden = false;
  el.sessions.appendChild(mk('div', 'hd', `会话（${state.sessions.length}）`));
  for (const s of state.sessions) {
    const row = mk('div', 'sess');
    row.setAttribute('aria-current', String(s.id === state.currentSessionId));
    const dot = mk('span', 'dot');
    dot.dataset.running = String(Boolean(s.running || s.state === 'running'));
    const title = mk('span', 't', s.title || s.id.slice(0, 18));
    const meta = mk('span', 'meta', [s.origin === 'subagent' ? '子' : '', s.running || s.state === 'running' ? '运行中' : ''].filter(Boolean).join(' '));
    row.append(dot, title, meta);
    row.onclick = () => selectSession(s.id);
    el.sessions.appendChild(row);
  }
}

function selectSession(sessionId) {
  if (state.currentSessionId === sessionId) return;
  state.currentSessionId = sessionId;
  state.messages.clear();
  state.tools.clear();
  state.cards.clear();
  el.feed.replaceChildren();
  el.composer.hidden = false;
  renderSessions();
  log('打开会话 ' + sessionId);
  state.client.history(sessionId, { limit: 60 });
  state.client.getPending(sessionId);
}

// ── feed rendering ───────────────────────────────────────────────────
function appendSys(text, tone) {
  const row = mk('div', 'sys', text);
  if (tone) row.dataset.tone = tone;
  el.feed.appendChild(row);
}

function renderDelta(p) {
  const sticky = atBottom();
  const mine = !p.sessionId || p.sessionId === state.currentSessionId;
  if (!mine) return;
  if (!p.messageId) return;

  let node = state.messages.get(p.messageId);
  if (!node) {
    node = mk('div', 'msg' + (p.role === 'user' ? ' user' : ''));
    el.feed.appendChild(node);
    state.messages.set(p.messageId, node);
  }
  if (typeof p.delta === 'string' && p.delta.length) node.textContent += p.delta;
  if (p.done) node.dataset.done = 'true';
  scrollIfSticky(sticky);
}

function renderTool(p) {
  const sticky = atBottom();
  const mine = !p.sessionId || p.sessionId === state.currentSessionId;
  if (!mine) return;
  const key = p.callId || 'anon';
  let node = state.tools.get(key);
  if (!node) {
    node = mk('div', 'tool');
    el.feed.appendChild(node);
    state.tools.set(key, node);
  }
  node.dataset.phase = p.phase;
  const bits = [];
  bits.push(`[${p.phase}]`);
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
    const b = mk('button', o.id === 'reject' ? 'ghost' : 'primary', o.label);
    b.onclick = () => {
      state.client.resolvePermission(p.sessionId ?? state.currentSessionId, p.requestId, o.id);
      card.remove();
      state.cards.delete(p.requestId);
    };
    opts.appendChild(b);
  }
  card.appendChild(opts);
  el.feed.appendChild(card);
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
        const b = mk('button', 'ghost', o.label);
        b.onclick = () => {
          if (q.multi) {
            if (chosen.has(o.id)) { chosen.delete(o.id); b.classList.remove('primary'); }
            else { chosen.add(o.id); b.classList.add('primary'); }
          } else {
            for (const sib of opts.children) sib.classList.remove('primary');
            chosen.clear();
            chosen.add(o.id);
            b.classList.add('primary');
          }
        };
        b.dataset.optionId = o.id;
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
  const submit = mk('button', 'primary', '提交');
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
  el.feed.appendChild(card);
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
      state.sessions = (p.sessions ?? []).slice().sort((a, b) =>
        String(b.updatedAt ?? '').localeCompare(String(a.updatedAt ?? '')));
      if (!state.currentSessionId) {
        const pick = state.sessions.find((s) => s.running || s.state === 'running') ?? state.sessions[0];
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
      appendSys(`载入 ${items.length} 条历史${p.nextBeforeSeq !== undefined ? '（还有更早的）' : ''}`);
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
      if (mine) {
        state.running = p.state === 'running';
        setStatus(p.state === 'running' ? '运行中' : '空闲', p.state === 'running' ? 'ok' : 'warn');
        appendSys(p.detail ? `${p.state} · ${p.detail}` : p.state);
      }
      return;
    }
    case 'ev.permission_request':
      renderPermission(p);
      return;
    case 'ev.permission_resolved':
      dropCard(p.requestId);
      appendSys('审批已由' + (p.by === 'desktop' ? '桌面' : '撤回') + '处理');
      return;
    case 'ev.question_request':
      renderQuestion(p);
      return;
    case 'ev.question_resolved':
      dropCard(p.requestId);
      return;
    case 'ev.host_info':
      appendSys(`主机 ${p.host?.platform ?? '?'}/${p.host?.arch ?? '?'} · DSH ${p.host?.dshVersion ?? '?'} · ${p.host?.carrier ?? ''}`);
      return;
    case 'ev.retry':
      appendSys(`模型重试 ${p.attempt}/${p.max}${p.reason ? ' · ' + p.reason : ''}`, 'warn');
      return;
    case 'ev.compaction':
      appendSys(`上下文压缩 ${p.state}${p.error ? ' · ' + p.error : ''}`, p.state === 'failed' ? 'err' : undefined);
      return;
    case 'ev.result':
      if (p.ok === false) appendSys('命令失败：' + (p.message ?? p.cmdId), 'err');
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

// ── wiring ───────────────────────────────────────────────────────────
function makeClient() {
  const client = new RemoteClient({
    onPayload: handlePayload,
    onStatus: (s, detail) => {
      if (s === 'ready') setStatus('已连接', 'ok');
      else if (s === 'connecting' || s === 'open' || s === 'pairing' || s === 'deriving') setStatus('连接中…', 'warn');
      else if (s === 'pair-fail' || s === 'need-repair' || s === 'error') setStatus('出错：' + (detail ?? ''), 'err');
      else if (s === 'closed') setStatus('已断开', 'err');
      else if (s === 'host-left') setStatus('主机离线', 'warn');
      else setStatus(s, 'warn');
      if (detail) log(`[${s}] ${detail}`);
    },
    onLog: log,
  });
  return client;
}

async function connect() {
  const uri = el.uri.value.trim();
  if (!uri) { log('请先粘贴配对 URI', 'warn'); return; }
  localStorage.setItem(STORE_KEY, uri);
  state.client?.stop();
  state.client = makeClient();
  state.currentSessionId = null;
  state.messages.clear();
  state.tools.clear();
  el.feed.replaceChildren();
  try {
    await state.client.start(uri);
    el.pairPanel.hidden = true;
  } catch (e) {
    setStatus('连接失败', 'err');
    log('连接失败：' + e.message, 'error');
    el.pairPanel.hidden = false;
  }
}

el.connect.onclick = connect;

el.forget.onclick = () => {
  localStorage.removeItem(STORE_KEY);
  el.uri.value = '';
  state.client?.stop();
  el.pairPanel.hidden = false;
  setStatus('已清除', 'warn');
};

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
el.interrupt.onclick = () => {
  if (state.currentSessionId) state.client?.interrupt(state.currentSessionId);
};
el.toggleLogs.onclick = () => { el.logs.hidden = !el.logs.hidden; };

// restore a saved pairing and connect automatically
if (envProblems.length) {
  setStatus('环境不满足', 'err');
  for (const problem of envProblems) {
    appendSys('✗ ' + problem, 'err');
    log(problem, 'error');
  }
  el.connect.disabled = true;
  el.pairPanel.hidden = false;
} else {
  const saved = localStorage.getItem(STORE_KEY);
  if (saved) {
    el.uri.value = saved;
    log('已载入上次的配对 URI');
    connect();
  } else {
    el.pairPanel.hidden = false;
    setStatus('未连接', 'warn');
    log('粘贴配对 URI 后点「连接并配对」');
  }
}
