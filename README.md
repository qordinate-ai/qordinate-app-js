# Qordinate App SDK

Authentication and authorization helper for MCP apps using Qordinate-issued JWTs.

NPM Package - https://www.npmjs.com/package/@qordinate-ai/app

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
  appSlug: "your-app-slug",                     // required, must match the token audience
  issuer: "https://auth.qordinate.ai",          // default if omitted, drives the JWKS resolution
  replayStore: new InMemoryReplayStore(),       // optional but recommended
  enableReplayProtection: true                  // defaults to false, enable to enforce single-use tokens.
});

const context = await authenticator.verifyAuthorizationHeader(
  req.headers.authorization,
  {
    requiredTools: ["calendar.create_event"],   // ensure token has access to the requested tool
    includeRawClaims: false                    
  }
);

// If you already have the raw JWT string, call verifyToken directly.
const ctx = await authenticator.verifyToken(token, ["calendar.create_event"], true);
```

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
