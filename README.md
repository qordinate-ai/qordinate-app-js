# Qordinate App SDK (Auth module)

Authentication and authorization helper for MCP apps using Qordinate-issued JWTs.

## Install

```sh
npm install @qordinate-ai/app
```

Requires Node 18+ (global `fetch`) and ES modules.

## Quick start

```ts
import { Authenticator, InMemoryReplayStore } from "@qordinate-ai/app/auth";
// or: import { Authenticator, InMemoryReplayStore } from "@qordinate-ai/app";

const authenticator = new Authenticator({
  appSlug: "your-app-slug",
  // issuer defaults to https://auth.qordinate.ai
  replayStore: new InMemoryReplayStore(),
  enableReplayProtection: true, // Defaults to false.
});

// In an HTTP handler
const context = await authenticator.verifyAuthorizationHeader(
  req.headers.authorization,
  {
    requiredTools: ["calendar.create_event"],
    includeRawClaims: false,
  }
);

// Use context.user.qid, context.actor, context.tools, context.token...
```

`verifyAuthorizationHeader` enforces:

- Bearer header presence and format
- RS256/ES256 signature via JWKS (`https://auth.qordinate.com/.well-known/jwks.json` by default)
- Issuer and audience (app slug)
- Claim shape: sub (E.164), qid, exp, iat, jti, actor, initiated_via, optional autonomous
- Tool permissions (`mcp.tools`) against your declared `requiredTools`
- Single-use tokens via replay store when enabled (409 on reuse)

Use `verifyToken(token, options)` when you already extracted the JWT string.

## Modules

- `auth` module exported as `import { Authenticator } from "@qordinate/app-sdk/auth"`.
- Future modules will get their own subpaths (e.g., `@qordinate/app-sdk/<module>`).

## Replay protection

Provide a store that satisfies:

```ts
interface ReplayStore {
  exists(jti: string): Promise<boolean> | boolean;
  store(jti: string, ttlSeconds: number): Promise<void> | void;
}
```

- Provide a `replayStore` implementation; in production use something durable (e.g., Redis).
- Use `enableReplayProtection: true` to enforce single-use tokens; it defaults to `false`.
- For local testing you can set `replayStore: new InMemoryReplayStore()` and choose whether to enable protection.

## Errors

Failures throw `AuthError` with `status` and `code`:

```
401 token_missing | invalid_authorization_header | invalid_signature | issuer_mismatch | token_expired | invalid_claim
403 audience_mismatch | tool_forbidden
409 replay_detected
500 server_error
```

Messages avoid leaking token content.

## Configuration

`AuthConfig`:

- `appSlug` (required)
- `issuer` (required, default JWKS: `${issuer}/.well-known/jwks.json`)
- `issuer` defaults to `https://auth.qordinate.com` if not provided
- `enableReplayProtection` defaults to `false`; set to `true` and supply a replay store to enforce single-use tokens
- `jwksUrl` (optional override)
- `replayStore` (recommended)
- `negativeCacheMs` (JWKS unknown-kid backoff, default 30s)

`VerifyOptions`:

- `requiredTools` (string[])
- `includeRawClaims` (boolean)

## Publish to npm

1. Authenticate: `npm login` (or set `NPM_TOKEN` and `.npmrc`).
2. Build artifacts: `npm run build`.
3. Version bump: `npm version patch` (or minor/major as needed).
4. Publish: `npm publish --access public` (omit `--access` if scoped/private registry).
5. Tag in git if desired: `git push && git push --tags`.

Ensure `dist/` exists from the build before publishing.
