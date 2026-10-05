# atlas-m2m-demo

Machine-to-machine auth with Atlas **API keys**, using the `@atlasauth/backend`
management client. A tenant mints long-lived keys for its own users /
organizations and verifies a key a machine presents on a later request.

## What's wired

- **`src/demo.js`** — a one-shot script: `atlas.apiKeys.create()` mints a key
  (the `ak_` secret is shown **once**), `atlas.apiKeys.verify(secret)` returns a
  `{ valid, subject_id, claims }` verdict, a `protectedEndpoint()` function gates
  on the key's embedded `scopes` claim, and `atlas.apiKeys.delete()` revokes it.
- **`src/server.js`** — the same verify logic behind a real HTTP route
  (`GET /reports`), authenticating `Authorization: Bearer ak_…`.

Keys are verified **online** (it is a credential check, rate-limited) — unlike
session JWTs, which `@atlasauth/backend` verifies locally.

## Run

```sh
npm install
cp .env.example .env     # set ATLAS_SECRET_KEY (sk_test_… / sk_live_…)

npm start                # runs the mint -> verify -> gate -> revoke script
# or run the protected server:
npm run serve
curl -H "Authorization: Bearer ak_live_xxx" http://localhost:3000/reports
```

## Packages

- `@atlasauth/backend` — `createAtlasClient(...).apiKeys.{create,verify,delete}`
