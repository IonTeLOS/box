import { Mailbox } from './mailbox.js';

// **export your DO class** so Wrangler knows about it
export { Mailbox };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split('/');
    const type = parts[1];       // "mailbox" or "room"
    const id   = parts[2];
    let ns, stub;

    if (type === 'mailbox') {
      ns   = env.MAILBOX;
      stub = ns.get(ns.idFromName(id));
    } else if (type === 'room') {
      ns   = env.ROOM;
      stub = ns.get(ns.idFromName(id));
    } else {
      return new Response('Not Found', { status: 404 });
    }

    // Forward the X-Owner-Id or X-Room-Id
    const headers = new Headers(request.headers);
    headers.set(type === 'mailbox' ? 'X-Owner-Id' : 'X-Room-Id', id);

    const forwarded = new Request(request.url, {
      method:  request.method,
      headers,
      body:    ['GET','HEAD'].includes(request.method) ? undefined : request.body,
      redirect: request.redirect,
    });

    return stub.fetch(forwarded, env);
  }
};
