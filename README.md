# Qordinate App SDK

Authentication and authorization helper for MCP apps using Qordinate-issued JWTs.

## Install

```sh
npm install @qordinate-ai/app
```

Requires Node 18+ (global `fetch`) and ES modules.

## Auth

Verify Qordinate-issued tokens before allowing your app to act.

```ts
import { Authenticator, InMemoryReplayStore } from "@qordinate-ai/app/auth";

const authenticator = new Authenticator({
  appSlug: "your-app-slug",
  issuer: "https://auth.qordinate.ai",          // default if omitted
  replayStore: new InMemoryReplayStore(),       // optional but recommended
  enableReplayProtection: true                  // defaults to false
});

const context = await authenticator.verifyAuthorizationHeader(
  req.headers.authorization,
  {
    requiredTools: ["calendar.create_event"],
    includeRawClaims: false
  }
);
```

- `appSlug` is required and must match the token audience.
- `issuer` defaults to `https://auth.qordinate.ai` and drives JWKS resolution.
- `requiredTools` ensures requested tool access is present in `mcp.tools`.
- Provide a `replayStore` and set `enableReplayProtection` to enforce single-use tokens.

`verifyAuthorizationHeader` enforces:

- Bearer header presence and format
- RS256/ES256 signature via JWKS (`https://auth.qordinate.ai/.well-known/jwks.json` by default)
- Issuer and audience (app slug)
- Claim shape: sub (E.164), qid, exp, iat, jti, actor, initiated_via, optional autonomous
- Tool permissions (`mcp.tools`) against your declared `requiredTools`
- Single-use tokens via replay store when enabled (409 on reuse)

Use `verifyToken(token, options)` when you already extracted the JWT string.

## Modules

- `auth` module exported as `import { Authenticator } from "@qordinate-ai/app/auth"` or root import.
- Future modules will get their own subpaths.

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
