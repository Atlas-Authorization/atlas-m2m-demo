// Atlas machine-to-machine / API-key demo.
//
// A tenant mints long-lived API keys for ITS OWN users or organizations, then
// asks Atlas to verify a key a machine presented on a later request. Only a hash
// is stored server-side, so the `ak_` secret is shown exactly ONCE at mint.
//
// Everything here goes through the Backend API (secret-key) client from
// `@atlasauth/backend`. Run with:  tsx --env-file=.env src/demo.ts
import { createAtlasClient, type AtlasClient } from '@atlasauth/backend';

const { ATLAS_SECRET_KEY, ATLAS_API_URL, DEMO_SUBJECT_ID = 'user_demo' } = process.env;

if (!ATLAS_SECRET_KEY) {
  console.error('Missing ATLAS_SECRET_KEY — copy .env.example and fill it in.');
  process.exit(1);
}

const atlas: AtlasClient = createAtlasClient({ secretKey: ATLAS_SECRET_KEY, apiUrl: ATLAS_API_URL });

interface EndpointResult {
  status: number;
  body: Record<string, unknown>;
}

async function main(): Promise<void> {
  // 1) Mint a key for a subject (a user or an organization). `claims` ride with
  //    the key and come back on every successful verify — use them for scopes.
  console.log('Minting an API key for', DEMO_SUBJECT_ID, '…');
  const minted = await atlas.apiKeys.create({
    subject_type: 'user',
    subject_id: DEMO_SUBJECT_ID,
    name: 'm2m-demo key',
    claims: { scopes: ['reports:read'] },
  });
  console.log('  key id:', minted.id, 'prefix:', minted.prefix);
  console.log('  SECRET (shown once):', minted.secret);

  // 2) Verify the presented secret. Every negative — unknown, revoked, expired —
  //    resolves to the SAME { valid: false }, so a caller learns nothing about
  //    which keys exist.
  const verdict = await atlas.apiKeys.verify(minted.secret);
  console.log('\nVerify a real key ->', verdict);

  const bogus = await atlas.apiKeys.verify('ak_this_is_not_a_real_key');
  console.log('Verify a bogus key ->', bogus);

  // 3) A protected endpoint, modelled as a plain function: it authenticates the
  //    caller purely from the presented key's verify verdict + claims.
  async function protectedEndpoint(presentedSecret: string): Promise<EndpointResult> {
    const v = await atlas.apiKeys.verify(presentedSecret);
    if (!v.valid) return { status: 401, body: { error: 'invalid_api_key' } };
    const scopes = Array.isArray(v.claims?.scopes) ? v.claims.scopes : [];
    if (!scopes.includes('reports:read')) {
      return { status: 403, body: { error: 'insufficient_scope' } };
    }
    return { status: 200, body: { subject: v.subject_id, report: 'the-protected-data' } };
  }

  console.log('\nCall protected endpoint with the key ->', await protectedEndpoint(minted.secret));
  console.log('Call protected endpoint with junk   ->', await protectedEndpoint('nope'));

  // 4) Clean up — revoke the demo key so it never authenticates again.
  await atlas.apiKeys.delete(minted.id);
  console.log('\nRevoked', minted.id);
}

main().catch((err) => {
  console.error('Demo failed:', err);
  process.exit(1);
});
