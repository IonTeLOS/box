// src/mailbox.js

export class Mailbox {
  sql;
  rateLimits = new Map();
  wsClients  = new Map();

  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.sql = ctx.storage.sql;

    // SCHEMA: run once per instance
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS settings(
        key TEXT PRIMARY KEY, value TEXT
      );
      CREATE TABLE IF NOT EXISTS contacts(
        peerId    TEXT PRIMARY KEY,
        publicKey TEXT, sharedKey BLOB,
        allowed   INTEGER, profile TEXT
      );
      CREATE TABLE IF NOT EXISTS inbox(
        id        TEXT PRIMARY KEY,
        fromPeer  TEXT, envelope BLOB,
        timestamp INTEGER
      );
      CREATE TABLE IF NOT EXISTS outbox(
        id        TEXT PRIMARY KEY,
        toPeer    TEXT, envelope BLOB,
        timestamp INTEGER
      );
      CREATE TABLE IF NOT EXISTS invites(
        token     TEXT PRIMARY KEY,
        initiator TEXT, expiresAt INTEGER,
        used      INTEGER
      );
      CREATE TABLE IF NOT EXISTS chat_sessions(
        sessionId    TEXT PRIMARY KEY,
        participants TEXT, createdAt INTEGER
      );
      CREATE TABLE IF NOT EXISTS storage_drives(
        driveId      TEXT PRIMARY KEY,
        owner        TEXT, participants TEXT,
        capacity     INTEGER, createdAt INTEGER
      );
    `);
  }

  // --- ENTRYPOINT ---
  async fetch(request) {
    const url     = new URL(request.url);
    const parts   = url.pathname.split("/");
    const ownerId = request.headers.get("X-Owner-Id") || request.headers.get("X-Room-Id");
    const path    = "/" + parts.slice(ownerId ? 3 : 2).join("/");
    const method  = request.method;

    // 1) SETUP-SECRET: one-time bootstrapping + default settings
    if (path === "/setup-secret" && method === "POST") {
      const existing = await this.ctx.storage.get("system_secret");
      if (existing) return new Response("Already initialized", { status: 409 });

      const { secret } = await request.json();
      await this.ctx.storage.put("system_secret", secret);

      // Insert defaults *once* at setup
      this.sql.exec(
        `INSERT OR IGNORE INTO settings(key,value) VALUES
           ('chainAnchored','false'),
           ('allowMessageRequests','false');`
      );
      return new Response("Secret stored", { status: 200 });
    }

    try {
      // ROTATE-SECRET
      if (path === "/rotate-secret" && method === "POST") {
        await this._requireOwner(ownerId, request);
        const newSecret = crypto.randomUUID() + Math.random();
        await this.ctx.storage.put("system_secret", newSecret);
        return new Response(JSON.stringify({ secret: newSecret }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      // RESET
      if (path === "/reset" && method === "POST") {
        await this._requireOwner(ownerId, request);
        for (const t of ["settings","contacts","inbox","outbox","invites","chat_sessions","storage_drives"]) {
          this.sql.exec(`DELETE FROM ${t};`);
        }
        await this.ctx.storage.delete("system_secret");
        return new Response("Reset complete", { status: 200 });
      }

      // INVITES
      if (path === "/invites" && method === "POST") {
        await this._requireOwner(ownerId, request);
        const { token, expiresIn = 3600 } = await request.json();
        const tok       = token || crypto.randomUUID();
        const expiresAt = Date.now() + expiresIn * 1000;
        this.sql.exec(
          `INSERT OR REPLACE INTO invites(token,initiator,expiresAt,used)
             VALUES(?,?,?,0);`,
           tok, ownerId, expiresAt, 0
        );
        return new Response(JSON.stringify({ token: tok,
          expiresAt,
          used: false      // brand new invite is always unused
        }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      if (path === "/invites" && method === "GET") {
        await this._requireOwner(ownerId, request);
        const raw = this.sql.exec(
         `SELECT token,initiator,expiresAt,used FROM invites;`
       ).toArray();
       // map used: 0/1 → false/true
       const rows = raw.map(r => ({
         token:     r.token,
         initiator: r.initiator,
         expiresAt: r.expiresAt,
         used:      Boolean(r.used)
       }));
       return new Response(JSON.stringify(rows), {
          headers: { "Content-Type": "application/json" }
        });
      }
      {
        const m = path.match(/^\/invites\/([^\/]+)\/redeem$/);
        if (m && method === "POST") {
          const token = m[1];
          const row   = this.sql.exec(
            `SELECT initiator,expiresAt,used FROM invites WHERE token=?;`,
            token
          ).toArray()[0];
          if (!row)   return new Response("Invalid invite", { status: 404 });
          const { initiator, expiresAt, used } = row;
          if (used)   return new Response("Already used", { status: 409 });
          if (Date.now() > expiresAt) return new Response("Expired", { status: 410 });

          const { peerId, publicKey, profile } = await request.json();
          const sharedKey = crypto.randomUUID() + Math.random();
          this.sql.exec(
            `INSERT OR REPLACE INTO contacts(peerId,publicKey,sharedKey,allowed,profile)
               VALUES(?,?,?,?,?);`,
             peerId, publicKey, sharedKey, 1, profile || null
          );
          this.sql.exec(
            `UPDATE invites SET used=1 WHERE token=?;`,
             token
          );
          return new Response(JSON.stringify({
             sharedKey,
             used: true    // once redeemed, we signal used=true
          }), {
            headers: { "Content-Type": "application/json" }
          });
        }
      }

      // GROUP ROOM
      if (path === "/rooms" && method === "POST") {
        await this._requireOwner(ownerId, request);
        const roomId     = crypto.randomUUID();
        const roomSecret = crypto.randomUUID() + Math.random();
        const roomNS     = this.env.ROOM;
        const roomStub   = roomNS.get(roomNS.idFromName(roomId));
        await roomStub.fetch(new Request(
          request.url.replace(/\/rooms$/, `/room/${roomId}/setup-secret`), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ secret: roomSecret })
          }
        ));
        const joinLink = `${url.origin}/room/${roomId}#${roomSecret}`;
        return new Response(JSON.stringify({ roomId, joinLink }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      // WebSocket
      if (method === "GET" && path === "/chat") {
        return this.handleWebSocket(request, ownerId);
      }

      // CONTACTS
      if (path === "/contacts" && method === "GET") {
        await this._requireOwner(ownerId, request);
        const rows = this.sql.exec(
          `SELECT peerId,publicKey,sharedKey,allowed,profile FROM contacts;`
        ).toArray();
        return new Response(JSON.stringify(rows), {
          headers: { "Content-Type": "application/json" }
        });
      }
      if (path === "/contacts" && method === "POST") {
        await this._requireOwner(ownerId, request);
        const { peerId, publicKey, sharedKey, allowed = 1, profile } = await request.json();
        this.sql.exec(
          `INSERT OR REPLACE INTO contacts(peerId,publicKey,sharedKey,allowed,profile)
             VALUES(?,?,?,?,?);`,
           peerId, publicKey, sharedKey, allowed, profile || null
        );
        return new Response("Contact added", { status: 200 });
      }

      // OUTBOX
      if (path === "/outbox" && method === "GET") {
        const rows = this.sql.exec(
          `SELECT id,toPeer,envelope,timestamp FROM outbox ORDER BY timestamp DESC;`
        ).toArray();
        return new Response(JSON.stringify(rows), {
          headers: { "Content-Type": "application/json" }
        });
      }
      if (path === "/outbox" && method === "POST") {
        await this._requireOwner(ownerId, request);
        const { id, toPeer, envelope } = await request.json();
        this.sql.exec(
          `INSERT OR IGNORE INTO outbox(id,toPeer,envelope,timestamp)
             VALUES(?,?,?,?);`,
           id, toPeer, envelope, Date.now()
        );
        return new Response("Published", { status: 201 });
      }


      // INBOX (with optional since & from filters)
if (path === "/inbox" && method === "GET") {
  await this._requireOwner(ownerId, request);
  const qp    = new URL(request.url).searchParams;
  const since = qp.has("since") ? Number(qp.get("since")) : null;
  const from  = qp.get("from");

  let sql     = `SELECT id, fromPeer, envelope, timestamp FROM inbox`;
  const params = [];
  const clauses = [];

  if (since !== null && !isNaN(since)) {
    clauses.push("timestamp >= ?");
    params.push(since);
  }
  if (from) {
    clauses.push("fromPeer = ?");
    params.push(from);
  }
  if (clauses.length) {
    sql += " WHERE " + clauses.join(" AND ");
  }
  sql += " ORDER BY timestamp DESC;";

  const stmt = params.length > 0
    ? this.sql.exec(sql, ...params)
    : this.sql.exec(sql);
  const rows = stmt.toArray();

  return new Response(JSON.stringify(rows), {
    headers: { "Content-Type": "application/json" }
  });
}

      if (path === "/inbox" && method === "POST") {
        const { sub: senderId } = await this._authenticate(request);
        const { id, envelope }  = await request.json();
        const row = this.sql.exec(
          `SELECT allowed FROM contacts WHERE peerId=?;`,
          senderId
        ).toArray()[0];
        // load the flag row and pull out its value
        const flagRows = this.sql.exec(
          `SELECT value FROM settings WHERE key='allowMessageRequests';`
        ).toArray();
        const openFlag = flagRows[0]?.value;
        if (!(row?.allowed) && openFlag !== "true") {
          throw this.error(403, "Forbidden");
        }
        this.sql.exec(
          `INSERT OR IGNORE INTO inbox(id,fromPeer,envelope,timestamp)
             VALUES(?,?,?,?);`,
           id, senderId, envelope, Date.now()
        );
        return new Response("Envelope received", { status: 201 });
      }
      if (path.startsWith("/inbox/") && method === "DELETE") {
        await this._requireOwner(ownerId, request);
        const id = path.split("/")[2];
        this.sql.exec(`DELETE FROM inbox WHERE id=?;`, id);
        return new Response("Deleted", { status: 200 });
      }

      // SETTINGS
      if (path === "/settings" && method === "GET") {
        await this._requireOwner(ownerId, request);
        // idempotent seed
        this.sql.exec(`
          INSERT OR IGNORE INTO settings(key,value) VALUES
            ('chainAnchored','false'),
            ('allowMessageRequests','false');
        `);
        const rows = this.sql.exec(`SELECT key,value FROM settings;`).toArray();
        return new Response(JSON.stringify(
          Object.fromEntries(rows.map(r => [r.key, r.value]))
        ), { headers: { "Content-Type": "application/json" } });
      }
      if (path === "/settings" && method === "PUT") {
        await this._requireOwner(ownerId, request);
        const { chainAnchored, allowMessageRequests } = await request.json();
        if (chainAnchored  !== undefined) this.sql.exec(
          `UPDATE settings SET value=? WHERE key='chainAnchored';`,
           chainAnchored
        );
        if (allowMessageRequests !== undefined) this.sql.exec(
          `UPDATE settings SET value=? WHERE key='allowMessageRequests';`,
           allowMessageRequests
        );
        return new Response("Settings updated", { status: 200 });
      }

      // fallback
      return new Response("Not Found", { status: 404 });
    } catch (err) {
      return new Response(err.message, { status: err.status || 500 });
    }
  }

  // --- Internal helpers ---
  async _requireOwner(ownerId, request) {
    const payload = await this._authenticate(request);
    if (payload.sub !== ownerId) throw this.error(403, "Owner only");
    return payload;
  }

  async _authenticate(request) {
    const auth  = request.headers.get("Authorization") || "";
    const token = auth.replace(/^Bearer\s+/, "");
    if (!token) throw this.error(401, "Missing token");
    // 1) Try system_secret (owner/admin)
    const systemSecret = await this.ctx.storage.get("system_secret");
    if (systemSecret) {
      try {
        return await verifyJwt(token, systemSecret);
      } catch {
        // fall through to sharedKey
      }
    }

    // 2) Try sharedKey for a peer
    // Decode header+payload to read 'sub' without verifying
    const parts = token.split('.');
    if (parts.length !== 3) throw this.error(401, "Invalid token format");
    const payload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(parts[1]))
    );
    const peerId = payload.sub;

    // Look up that contact’s sharedKey
    const row = this.sql.exec(
      `SELECT sharedKey,allowed FROM contacts WHERE peerId=?;`,
      peerId
    ).toArray()[0];
    if (!row || row.allowed !== 1) {
      throw this.error(403, "Forbidden: not a contact");
    }

    // Verify with the sharedKey
    return await verifyJwt(token, row.sharedKey);
  }

  error(status, message) {
    const e = new Error(message);
    e.status = status;
    return e;
  }

  // --- WebSocket support ---
  async handleWebSocket(request, ownerId) {
    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();

    server.addEventListener("open", async () => {
      try {
        const token = new URL(request.url).searchParams.get("token");
        if (!token) throw new Error("Missing token");

        // Only system_secret may open a socket
        const systemSecret = await this.ctx.storage.get("system_secret");
        if (!systemSecret) throw new Error("Secret not initialized");

        const payload = await verifyJwt(token, systemSecret);
        if (payload.sub !== ownerId) throw new Error("Not owner");

        // Owner is authenticated—keep their socket
        this.wsClients.set(ownerId, server);

      } catch (err) {
        // Unauthorized—close immediately
        server.close(1008, "Unauthorized");
      }
    });

    // We don’t need to proxy any incoming messages on this socket,
    // it’s one-way (server → client) for notifications.
      server.addEventListener("message", () => {
      // ignore
    });

    return new Response(null, { status: 101, webSocket: client });
  }
}

// --- JWT Helpers ---
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (str.length % 4)) % 4;
  str += '='.repeat(pad);
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function verifyJwt(token, secret) {
  const [h, p, s] = token.split('.');
  if (!s) throw new Error('Invalid token');
  const data      = new TextEncoder().encode(`${h}.${p}`);
  const signature = base64urlDecode(s);
  const key       = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) throw new Error('Invalid or expired token');
  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(p)));
  const now     = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('Token expired');
  return payload;
}
