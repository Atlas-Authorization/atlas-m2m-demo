// A tiny HTTP server whose single route is protected by an Atlas API key.
// The machine client presents its key as `Authorization: Bearer ak_…`; the
// server verifies it online via @atlasauth/backend and gates on the key's
// embedded scopes. No extra web framework — Node's built-in http.
//
// Run:   node --env-file=.env src/server.js
// Call:  curl -H "Authorization: Bearer ak_live_xxx" http://localhost:3000/reports
import { createServer } from 'node:http';
import { createAtlasClient } from '@atlasauth/backend';

const { ATLAS_SECRET_KEY, ATLAS_API_URL, PORT = '3000' } = process.env;
if (!ATLAS_SECRET_KEY) {
  console.error('Missing ATLAS_SECRET_KEY — copy .env.example and fill it in.');
  process.exit(1);
}

const atlas = createAtlasClient({ secretKey: ATLAS_SECRET_KEY, apiUrl: ATLAS_API_URL });

const send = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

createServer(async (req, res) => {
  if (req.url !== '/reports') return send(res, 404, { error: 'not_found' });

  const header = req.headers.authorization ?? '';
  const secret = header.startsWith('Bearer ') ? header.slice(7) : '';

  const v = await atlas.apiKeys.verify(secret);
  if (!v.valid) return send(res, 401, { error: 'invalid_api_key' });

  const scopes = Array.isArray(v.claims?.scopes) ? v.claims.scopes : [];
  if (!scopes.includes('reports:read')) return send(res, 403, { error: 'insufficient_scope' });

  return send(res, 200, { subject: v.subject_id, report: 'the-protected-data' });
}).listen(Number(PORT), () => {
  console.log(`atlas-m2m-demo server on http://localhost:${PORT} (GET /reports)`);
});
