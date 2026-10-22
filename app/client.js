/**
 * client.js — a minimal DSH Remote Control client speaking the public protocol.
 *
 * Contract sources:
 *   @dsh-remote/protocol/dist/src/wire/frames.js      relay frames (control plane)
 *   @dsh-remote/protocol/dist/src/wire/payloads.js    cmd.* / ev.* payloads (sealed)
 *   @dsh-remote/plugin/dist/bundle/index.js           C2H='c2h', H2C='h2c'
 *
 * Flow:  hello{role:client,protocol:1} → hello-ok → pair-begin-client{token} → paired
 *        → derive kC2H/kH2C → WAIT for the host's first sealed frame (ev.host_info)
 *        → only then may we send commands.
 *
 * Two rules this client must not break (the host enforces both, silently):
 *   1. Sending an uplink `enc` for an unknown conversation voids the pairing.
 *      A freshly paired convId is not registered on the host until it has derived
 *      its keys, so we stay quiet until its first frame arrives.
 *   2. Two consecutive undecryptable frames void the pairing outright. So decryption
 *      correctness is a hard requirement, not a nice-to-have (proved in test-crypto).
 *
 * Nonce choice: the protocol's client direction uses a counter nonce bound to an
 * install id. In a browser the counter resets on page reload while the install id
 * persists in localStorage, which would reuse (key, nonce) — catastrophic for
 * XSalsa20. The host does not validate the prefix, and the receiver always reads the
 * nonce out of the record, so we send a fresh random 24-byte nonce per frame.
 */
import { derivePskKey, seal, open, toBase64, randomBytes, NONCE_BYTES } from './crypto.js';

export const PROTOCOL_VERSION = 1;
const PING_MS = 25_000;
const RECONNECT_MS = 2_000;

/** Parse `dshr:/p?v=1&s=wss://…&n=label&psk=<b64>[&t=<6 digits>]`. */
export function parsePairingUri(text) {
  const raw = String(text ?? '').trim();
  if (!raw.startsWith('dshr:/p?')) return null;
  const qs = raw.slice(raw.indexOf('?') + 1);
  let params;
  try {
    params = new URLSearchParams(qs);
  } catch {
    return null;
  }
  const server = params.get('s') ?? '';
  const psk = params.get('psk') ?? '';
  if (!server || !psk) return null;
  if (!/^wss?:\/\//.test(server)) return null;
  const token = params.get('t') ?? '';
  return {
    v: Number(params.get('v') ?? 1),
    server,
    hostLabel: params.get('n') || 'dsh',
    psk,
    token: /^\d{6}$/.test(token) ? token : '',
  };
}

const newId = (prefix) => prefix + toBase64(randomBytes(9)).replace(/[^A-Za-z0-9]/g, '').slice(0, 12);

export class RemoteClient {
  /**
   * @param {object} handlers
   * @param {(payload: any) => void} handlers.onPayload  decrypted ev.* payload
   * @param {(state: string, detail?: string) => void} handlers.onStatus
   * @param {(line: string, level?: string) => void} handlers.onLog
   */
  constructor(handlers = {}) {
    this.onPayload = handlers.onPayload ?? (() => {});
    this.onStatus = handlers.onStatus ?? (() => {});
    this.onLog = handlers.onLog ?? (() => {});

    this.ws = null;
    this.pairing = null;      // parsed URI
    this.convId = null;       // pairing channel id (c_xxx) == paired.sessionId
    this.hostId = null;
    this.clientId = null;     // authoritative id from hello-ok
    this.kC2H = null;         // outbound key
    this.kH2C = null;         // inbound key
    this.seq = 0;
    this.pingTimer = null;
    this.reconnectTimer = null;
    this.closedByUser = false;
    /** Commands are refused until the host has proved it can talk to us. */
    this.canCommand = false;
    this.badFramesInARow = 0;
    this.warnedBadFrame = false;
  }

  log(line, level = 'info') { this.onLog(line, level); }

  async start(pairingUri) {
    const parsed = parsePairingUri(pairingUri);
    if (!parsed) throw new Error('配对 URI 无法识别（应以 dshr:/p? 开头，且含 s= 与 psk=）');
    this.pairing = parsed;
    this.closedByUser = false;
    await this.openSocket();
  }

  stop() {
    this.closedByUser = true;
    this.clearTimers();
    try { this.ws?.close(); } catch {}
    this.ws = null;
    this.canCommand = false;
    this.onStatus('stopped');
  }

  clearTimers() {
    if (this.pingTimer) { clearInterval(this.pingTimer); this.pingTimer = null; }
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
  }

  openSocket() {
    return new Promise((resolve, reject) => {
      const url = this.pairing.server;
      this.onStatus('connecting', url);
      let ws;
      try {
        ws = new WebSocket(url);
      } catch (e) {
        reject(e);
        return;
      }
      this.ws = ws;
      let settled = false;

      ws.onopen = () => {
        this.onStatus('open', url);
        const hello = {
          t: 'hello',
          role: 'client',
          protocol: PROTOCOL_VERSION,
          clientId: this.clientId ?? newId('cli-'),
          clientMeta: { platform: 'web', label: 'dsh-remote-web' },
          ...(this.hostId ? { hostId: this.hostId } : {}),
        };
        this.sendRaw(hello);
        if (!settled) { settled = true; resolve(); }
      };

      ws.onmessage = (ev) => {
        let frame;
        try { frame = JSON.parse(typeof ev.data === 'string' ? ev.data : String(ev.data)); }
        catch { return; }
        try { this.handleFrame(frame); }
        catch (e) { this.log('处理帧异常：' + e.message, 'error'); }
      };

      ws.onerror = () => { this.onStatus('error'); };

      ws.onclose = (ev) => {
        this.clearTimers();
        this.canCommand = false;
        if (!settled) { settled = true; reject(new Error('WebSocket 连接失败（code ' + ev.code + '）')); return; }
        if (this.closedByUser) return;
        this.onStatus('closed', 'code ' + ev.code);
        this.log(`连接断开（code ${ev.code}），${RECONNECT_MS / 1000}s 后重连`, 'warn');
        this.reconnectTimer = setTimeout(() => {
          this.openSocket().catch((e) => this.log('重连失败：' + e.message, 'error'));
        }, RECONNECT_MS);
      };
    });
  }

  sendRaw(obj) {
    if (this.ws?.readyState !== 1) return false;
    this.ws.send(JSON.stringify(obj));
    return true;
  }

  handleFrame(frame) {
    switch (frame.t) {
      case 'hello-ok': {
        this.clientId = frame.clientId ?? this.clientId;
        this.hostId = frame.hostId ?? this.hostId;
        this.log(`中继已登记：clientId=${this.clientId} protocol=${frame.protocol}`);

        if (this.convId && this.kC2H) {
          // Reconnect to a conversation the host already knows: the documented resume
          // path is to go straight to cmd.list_sessions, which also triggers the host's
          // "client rejoined" handling.
          this.canCommand = true;
          this.onStatus('ready', 'reconnected');
          this.startPing();
          this.sendCommand({ t: 'cmd.list_sessions', cmdId: newId('cmd-') });
          this.sendCommand({ t: 'cmd.get_pending', cmdId: newId('cmd-') });
          return;
        }
        if (this.pairing.token) {
          this.sendRaw({ t: 'pair-begin-client', pairingToken: this.pairing.token });
          this.onStatus('pairing');
        } else {
          this.log('配对 URI 里没有 6 位配对码（t=），无法配对', 'error');
          this.onStatus('no-token');
        }
        return;
      }

      case 'paired': {
        this.convId = frame.sessionId;
        this.hostId = frame.hostId ?? this.hostId;
        this.onStatus('deriving');
        this.deriveKeys()
          .then(() => {
            // Deliberately NOT ready to command yet: the host has not registered this
            // conversation, and an early uplink frame voids the pairing.
            this.onStatus('waiting-host');
            this.log(`已配对，通道 ${this.convId}（host ${this.hostId}）；等待主机的第一帧`);
            this.startPing();
          })
          .catch((e) => {
            this.log('密钥派生失败：' + e.message, 'error');
            this.onStatus('error', 'derive');
          });
        return;
      }

      case 'pair-fail': {
        const zh = {
          invalid_or_expired: '配对码无效或已过期（请在 pill 上重新生成）',
          already_used: '配对码已被使用',
          host_offline: '主机不在线',
          bad_token: '配对码错误',
        };
        const msg = zh[frame.reason] ?? frame.reason;
        this.log('配对失败：' + msg, 'error');
        this.onStatus('pair-fail', msg);
        return;
      }

      case 'enc':
      case 'enc-batch': {
        const items = frame.t === 'enc-batch' ? frame.items : [{ ciphertext: frame.ciphertext }];
        for (const item of items) this.handleRecord(item);
        return;
      }

      case 'peer-joined':
        this.log('主机侧已确认连接');
        return;

      case 'peer-left':
        this.log(frame.unpaired ? '主机已解除配对' : '主机离线（会话保留，可重连）', 'warn');
        if (frame.unpaired) { this.canCommand = false; this.convId = null; this.kC2H = null; this.kH2C = null; }
        this.onStatus(frame.unpaired ? 'unpaired' : 'host-left');
        return;

      case 'ping':
        this.sendRaw({ t: 'pong', ...(typeof frame.ts === 'number' ? { ts: frame.ts } : {}) });
        return;

      case 'pong':
        return;

      case 'error': {
        this.log(`中继错误：${frame.code}${frame.message ? ' — ' + frame.message : ''}`, 'error');
        if (frame.code === 'unknown_session' || frame.code === 'not_member') {
          // The only signals that mean "the pairing is gone".
          this.convId = null;
          this.kC2H = null;
          this.kH2C = null;
          this.canCommand = false;
          this.onStatus('need-repair', frame.message ?? frame.code);
        } else if (frame.code === 'unsupported_protocol') {
          this.onStatus('error', frame.message ?? '协议版本不匹配');
        } else {
          this.onStatus('error', frame.code);
        }
        return;
      }

      default:
        this.log('未识别的帧：' + String(frame.t), 'warn');
    }
  }

  handleRecord(item) {
    if (!this.kH2C) return;
    const payload = open(this.kH2C, item);
    if (!payload) {
      this.badFramesInARow += 1;
      if (!this.warnedBadFrame) {
        this.warnedBadFrame = true;
        this.log('有帧解不开（密钥/通道不匹配）— 主机连续两帧解不开会作废配对', 'warn');
      }
      return;
    }
    this.badFramesInARow = 0;

    if (!this.canCommand) {
      // First readable frame from the host: it has registered us, so uplink is safe now.
      this.canCommand = true;
      this.onStatus('ready', 'paired');
      this.log('主机已通，开始拉取会话');
      this.sendCommand({ t: 'cmd.list_sessions', cmdId: newId('cmd-') });
      this.sendCommand({ t: 'cmd.get_pending', cmdId: newId('cmd-') });
    }

    try { this.onPayload(payload); }
    catch (e) { this.log('载荷处理异常：' + e.message, 'error'); }
  }

  async deriveKeys() {
    this.kC2H = await derivePskKey(this.pairing.psk, 'c2h', this.convId);
    this.kH2C = await derivePskKey(this.pairing.psk, 'h2c', this.convId);
  }

  startPing() {
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = setInterval(() => this.sendRaw({ t: 'ping', ts: Date.now() }), PING_MS);
  }

  /** Seal a cmd.* payload and send it as an `enc` frame (random nonce per frame). */
  sendCommand(payload) {
    if (!this.canCommand || !this.kC2H) {
      this.log('尚未就绪，命令未发送：' + payload.t, 'warn');
      return false;
    }
    const record = seal(this.kC2H, payload, randomBytes(NONCE_BYTES));
    this.seq += 1;
    // The relay injects clientId itself; sending our own is at best redundant.
    return this.sendRaw({ t: 'enc', sessionId: this.convId, seq: this.seq, ciphertext: record.ciphertext });
  }

  // ── convenience commands ────────────────────────────────────────────
  listSessions() { return this.sendCommand({ t: 'cmd.list_sessions', cmdId: newId('cmd-') }); }

  history(sessionId, opts = {}) {
    return this.sendCommand({
      t: 'cmd.session_history',
      cmdId: newId('cmd-'),
      sessionId,
      ...(opts.since !== undefined ? { since: opts.since } : {}),
      ...(opts.beforeSeq !== undefined ? { beforeSeq: opts.beforeSeq } : {}),
      ...(opts.limit !== undefined ? { limit: opts.limit } : {}),
    });
  }

  sendPrompt(sessionId, text) {
    return this.sendCommand({ t: 'cmd.send_prompt', cmdId: newId('cmd-'), sessionId, text });
  }

  interrupt(sessionId) {
    return this.sendCommand({ t: 'cmd.interrupt', cmdId: newId('cmd-'), sessionId });
  }

  resolvePermission(sessionId, requestId, decision) {
    return this.sendCommand({ t: 'cmd.resolve_permission', cmdId: newId('cmd-'), sessionId, requestId, decision });
  }

  answer(sessionId, requestId, answers) {
    return this.sendCommand({ t: 'cmd.answer', cmdId: newId('cmd-'), sessionId, requestId, answers });
  }

  getPending(sessionId) {
    return this.sendCommand({ t: 'cmd.get_pending', cmdId: newId('cmd-'), ...(sessionId ? { sessionId } : {}) });
  }
}
