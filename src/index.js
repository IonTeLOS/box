// src/index.js
// Entrypoint for the Cloudflare Worker routing to the Mailbox Durable Object

import { Mailbox } from './mailbox';

// Export the Durable Object class so Wrangler can register it
export { Mailbox };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const [, resource, ownerId] = url.pathname.split('/');

    // Route requests under /mailbox/:ownerId/* to the Durable Object
    if (resource === 'mailbox' && ownerId) {
      // Generate a deterministic ID for this owner
      const id = env.MAILBOX.idFromName(ownerId);
      const stub = env.MAILBOX.get(id);
      // Attach ownerId header for the DO
      const modifiedHeaders = new Headers(request.headers);
      modifiedHeaders.set('X-Owner-Id', ownerId);
      const newRequest = new Request(request.url, {
        method: request.method,
        headers: modifiedHeaders,
        body: ['GET','HEAD'].includes(request.method) ? undefined : request.body,
        redirect: request.redirect
      });
      // Forward the modified request to the DO
      return stub.fetch(newRequest, env);
    }

    // No matching route: 404
    return new Response('Not Found', { status: 404 });
  }
};
