// src/mailbox.js
// Cloudflare Worker Durable Object for encrypted messaging
// ================================================================

// ENVIRONMENT VARIABLES:
// - SYSTEM_SECRET: HS256 JWT signing secret
// - POLY_RPC_URL: Polygon JSON-RPC endpoint
// Bindings:
// - env.PAYLOAD_BUCKET: R2 bucket for encrypted payloads

export class Mailbox {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.initialized = false;
    this.rateLimits = new Map();
    this.wsClients = new Map();
  }

  // Initialize SQLite schema once per DO instance
  async initialize() {
    if (this.initialized) return;
    this.db = await this.state.storage.sqlite(
      `
      CREATE TABLE IF NOT EXISTS contacts (
        peerId TEXT PRIMARY KEY,
        publicKey TEXT,
        sharedKey BLOB,
        allowed INTEGER
      );
      CREATE TABLE IF NOT EXISTS inbox (
        id TEXT PRIMARY KEY,
        fromPeer TEXT,
        envelope BLOB,
        timestamp INTEGER
      );
      CREATE TABLE IF NOT EXISTS outbox (
        id TEXT PRIMARY KEY,
        toPeer TEXT,
        payloadKey TEXT,
        txHash TEXT,
        timestamp INTEGER
      );
      CREATE TABLE IF NOT EXISTS storage_drives (
        driveId TEXT PRIMARY KEY,
        owner TEXT,
        participants TEXT,
        capacity INTEGER,
        createdAt INTEGER
      );
      CREATE TABLE IF NOT EXISTS chat_sessions (
        sessionId TEXT PRIMARY KEY,
        participants TEXT,
        createdAt INTEGER
      );
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );
      CREATE TABLE IF NOT EXISTS inbox_requests (
        id TEXT PRIMARY KEY,
        fromPeer TEXT,
        envelope BLOB,
        status TEXT,
        timestamp INTEGER
      );
      `
    );
    // Insert default settings if missing
    await this.db.run(`INSERT OR IGNORE INTO settings(key,value) VALUES('chainAnchored','false')`);
    await this.db.run(`INSERT OR IGNORE INTO settings(key,value) VALUES('allowMessageRequests','false')`);
    this.initialized = true;
  }

  // Authenticate JWT; if requireOwner, enforce payload.sub === ownerId
  async authenticate(request, { requireOwner = false, ownerId } = {}) {
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace(/^Bearer\s+/, '');
    if (!token) throw this.error(401, 'Missing token');
    let payload;
    try {
      payload = await verifyJwt(token, this.env.SYSTEM_SECRET);
    } catch {
      throw this.error(401, 'Invalid or expired token');
    }
    if (requireOwner && payload.sub !== ownerId) {
      throw this.error(403, 'Forbidden: owner only');
    }
    return payload;
  }

  error(status, message) {
    const e = new Error(message);
    e.status = status;
    return e;
  }

  // Main fetch entrypoint
  async fetch(request, env) {
    await this.initialize();
    const url = new URL(request.url);
    const segments = url.pathname.split('/');
    // URL format: /mailbox/:ownerId/...rest
    const ownerId = segments[2];
    const path = '/' + segments.slice(3).join('/');
    const method = request.method;

    // WebSocket chat upgrade
    if (method === 'GET' && path === '/chat') {
      return this.handleWebSocket(request, ownerId);
    }

    try {
      // SETTINGS
      if (path === '/settings' && method === 'GET') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        return this.handleGetSettings();
      }
      if (path === '/settings' && method === 'PUT') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const updates = await request.json();
        return this.handleUpdateSettings(updates);
      }

      // CONTACTS (owner only)
      if (path === '/contacts' && method === 'POST') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const body = await request.json();
        return this.handleAddContact(body);
      }

      // OUTBOX
      if (path === '/outbox' && method === 'GET') {
        return this.handleListOutbox();
      }
      if (path === '/outbox' && method === 'POST') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const body = await request.json();
        return this.handlePublishPayload(body, ownerId);
      }

      // INBOX
      if (path === '/inbox' && method === 'GET') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        return this.handleListInbox();
      }
      if (path === '/inbox' && method === 'POST') {
        const { sub: senderId } = await this.authenticate(request, { ownerId });
        const body = await request.json();
        return this.handleReceiveEnvelope(senderId, body, ownerId);
      }
      if (path.startsWith('/inbox/') && method === 'DELETE') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const id = path.split('/')[2];
        return this.handleDeleteInbox(id);
      }

      // INBOX REQUESTS
      if (path === '/inbox/request' && method === 'POST') {
        const body = await request.json();
        return this.handleInboxRequest(body, ownerId);
      }
      if (path === '/inbox/requests' && method === 'GET') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        return this.handleListRequests();
      }
      if (path.startsWith('/inbox/requests/') && method === 'POST') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const peerId = path.split('/')[2];
        return this.handleApproveRequest(peerId);
      }

      // PAYLOAD URL (owner only)
      if (path.startsWith('/payload/') && method === 'GET') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const key = path.split('/')[2];
        return this.handleGetPayloadUrl(key);
      }

      // SHARED STORAGE DRIVE
      if (path === '/shared-storage-drive' && method === 'POST') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const body = await request.json();
        return this.handleCreateDrive(body, ownerId);
      }
      if (path.startsWith('/shared-storage-drive/') && method === 'GET') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const driveId = path.split('/')[2];
        return this.handleGetDrive(driveId);
      }
      if (path.startsWith('/shared-storage-drive/') && method === 'PUT') {
        await this.authenticate(request, { requireOwner: true, ownerId });
        const driveId = path.split('/')[2];
        const body = await request.json();
        return this.handleUpdateDrive(driveId, body);
      }

      // Fallback 404
      return new Response('Not Found', { status: 404 });

    } catch (err) {
      return new Response(err.message, { status: err.status || 500 });
    }
  }

  // --- Handlers implementation follows ---
  async handleGetSettings() {
    const rows = await this.db.all(`SELECT * FROM settings`);
    return new Response(JSON.stringify(Object.fromEntries(rows.map(r => [r.key, r.value]))), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async handleUpdateSettings(body) {
    const { chainAnchored, allowMessageRequests } = body;
    if (chainAnchored !== undefined) {
      await this.db.run(`UPDATE settings SET value = ? WHERE key = 'chainAnchored'`, [chainAnchored]);
    }
    if (allowMessageRequests !== undefined) {
      await this.db.run(`UPDATE settings SET value = ? WHERE key = 'allowMessageRequests'`, [allowMessageRequests]);
    }
    return new Response('Settings updated', { status: 200 });
  }

  async handleAddContact({ peerId, publicKey, envKey }) {
    await this.db.run(
      `INSERT OR REPLACE INTO contacts(peerId, publicKey, sharedKey, allowed)
       VALUES (?, ?, ?, 1)`,
      [peerId, publicKey, atob(envKey)]
    );
    return new Response('Contact added', { status: 200 });
  }

  async handleListOutbox() {
    const rows = await this.db.all(
      `SELECT id, toPeer, payloadKey, txHash, timestamp FROM outbox ORDER BY timestamp DESC`
    );
    return new Response(JSON.stringify(rows), { headers: { 'Content-Type': 'application/json' } });
  }

  async handlePublishPayload({ id, toPeer, payloadBlob }) {
    await this.env.PAYLOAD_BUCKET.put(id, payloadBlob);
    const [{ value: chainFlag }] = await this.db.all(`SELECT value FROM settings WHERE key = 'chainAnchored'`);
    let txHash = null;
    if (chainFlag === 'true') txHash = await this.anchorOnChain(id);
    await this.db.run(
      `INSERT OR IGNORE INTO outbox(id, toPeer, payloadKey, txHash, timestamp)
       VALUES (?, ?, ?, ?, ?)`,
      [id, toPeer, id, txHash, Date.now()]
    );
    await notify(toPeer, { type: 'new_message', from: ownerId, id });
    return new Response('Published', { status: 201 });
  }

  async handleListInbox() {
    const rows = await this.db.all(
      `SELECT id, fromPeer, envelope, timestamp FROM inbox ORDER BY timestamp DESC`
    );
    return new Response(JSON.stringify(rows), { headers: { 'Content-Type': 'application/json' } });
  }

  async handleReceiveEnvelope(senderId, { id, envelope }) {
    this.enforceRateLimit(senderId);
    const [{ value: openFlag }] = await this.db.all(`SELECT value FROM settings WHERE key = 'allowMessageRequests'`);
    const contact = await this.db.get(`SELECT allowed FROM contacts WHERE peerId = ?`, [senderId]);
    if (!contact?.allowed && openFlag !== 'true') throw this.error(403, 'Forbidden');
    await this.db.run(
      `INSERT OR IGNORE INTO inbox(id, fromPeer, envelope, timestamp)
       VALUES (?, ?, ?, ?)`,
      [id, senderId, envelope, Date.now()]
    );
    await notify(ownerId, { type: 'new_envelope', from: senderId, id });
    return new Response('Envelope received', { status: 201 });
  }

  async handleDeleteInbox(id) {
    await this.db.run(`DELETE FROM inbox WHERE id = ?`, [id]);
    return new Response('Deleted', { status: 200 });
  }

  async handleInboxRequest({ id, fromPeer, envelope }) {
    const [{ value: openFlag }] = await this.db.all(`SELECT value FROM settings WHERE key = 'allowMessageRequests'`);
    if (openFlag !== 'true') throw this.error(403, 'Requests disabled');
    await this.db.run(
      `INSERT OR IGNORE INTO inbox_requests(id, fromPeer, envelope, status, timestamp)
       VALUES (?, ?, ?, ?, ?)`,
      [id, fromPeer, envelope, 'pending', Date.now()]
    );
    await notify(ownerId, { type: 'inbox_request', from: fromPeer, id });
    return new Response('Request submitted', { status: 202 });
  }

  async handleListRequests() {
    const rows = await this.db.all(`SELECT * FROM inbox_requests ORDER BY timestamp DESC`);
    return new Response(JSON.stringify(rows), { headers: { 'Content-Type': 'application/json' } });
  }

  async handleApproveRequest(peerId) {
    await this.db.run(`UPDATE inbox_requests SET status = 'approved' WHERE fromPeer = ?`, [peerId]);
    await this.db.run(
      `INSERT OR REPLACE INTO contacts(peerId, publicKey, sharedKey, allowed)
       VALUES (?, '', '', 1)`,
      [peerId]
    );
    return new Response('Approved', { status: 200 });
  }

  async handleGetPayloadUrl(key) {
    const url = await this.env.PAYLOAD_BUCKET.getSignedUrl(key, { expiration: 3600 });
    return new Response(JSON.stringify({ url }), { headers: { 'Content-Type': 'application/json' } });
  }

  async handleCreateDrive({ driveId, participants, capacity }) {
    await this.db.run(
      `INSERT INTO storage_drives(driveId, owner, participants, capacity, createdAt)
       VALUES (?, ?, ?, ?, ?)`,
      [driveId, ownerId, JSON.stringify(participants), capacity, Date.now()]
    );
    return new Response('Drive created', { status: 201 });
  }

  async handleGetDrive(driveId) {
    const row = await this.db.get(`SELECT * FROM storage_drives WHERE driveId = ?`, [driveId]);
    return new Response(JSON.stringify(row), { headers: { 'Content-Type': 'application/json' } });
  }

  async handleUpdateDrive(driveId, { participants, capacity }) {
    await this.db.run(
      `UPDATE storage_drives SET participants = ?, capacity = ? WHERE driveId = ?`,
      [JSON.stringify(participants), capacity, driveId]
    );
    return new Response('Drive updated', { status: 200 });
  }

  async handleWebSocket(request) {
    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    server.addEventListener('open', async () => {
      const url = new URL(request.url);
      const token = url.searchParams.get('token');
      const peerId = (await verifyJwt(token, this.env.SYSTEM_SECRET)).sub;
      this.wsClients.set(peerId, server);
    });
    server.addEventListener('message', async (e) => {
      const msg = JSON.parse(e.data);
      const { sessionId, participants, content } = msg;
      for (const p of participants) {
        if (p !== ownerId) {
          const ws = this.wsClients.get(p);
          if (ws) ws.send(JSON.stringify(msg));
        }
      }
      await this.db.run(
        `INSERT OR IGNORE INTO chat_sessions(sessionId,participants,createdAt) VALUES(?,?,?)`,
        [sessionId, JSON.stringify(participants), Date.now()]
      );
      for (const p of participants) {
        if (p !== ownerId) await notify(p, { type: 'chat_message', from: ownerId, sessionId });
      }
    });
    return new Response(null, { status: 101, webSocket: client });
  }

  enforceRateLimit(peerId) {
    const limit = 10;
    const windowMs = 60000;
    const now = Date.now();
    let entry = this.rateLimits.get(peerId) || { count: 0, start: now };
    if (now - entry.start > windowMs) entry = { count: 0, start: now };
    entry.count++;
    this.rateLimits.set(peerId, entry);
    if (entry.count > limit) throw this.error(429, 'Rate limit exceeded');
  }

  async anchorOnChain(id) {
    const body = { jsonrpc: '2.0', method: 'eth_sendRawTransaction', params: ['0x...'], id: 1 };
    const resp = await fetch(this.env.POLY_RPC_URL, { method: 'POST', body: JSON.stringify(body) });
    const json = await resp.json();
    return json.result || null;
  }
}

// Pluggable notification adapter stub
async function notify(userId, payload) {
  // TODO: implement FCM or ntfy logic
}

// Helpers
function atob(str) {
  return Buffer.from(str, 'base64');
}

async function verifyJwt(token, secret) {
  throw new Error('verifyJwt not implemented');
}
