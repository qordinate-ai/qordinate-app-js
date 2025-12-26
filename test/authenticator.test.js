import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import { Authenticator, AuthError, InMemoryReplayStore } from "../dist/index.js";

const APP_SLUG = "app-under-test";
const HOSTED_JWKS_URL = "https://auth.qordinate.ai/.well-known/jwks.json";

async function makeKey(kid = randomUUID()) {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  return { kid, privateKey, jwk: { ...jwk, kid, alg: "RS256", use: "sig" } };
}

async function startJwksServer(keys) {
  let jwks = { keys };
  let hits = 0;
  const server = createServer((req, res) => {
    if (req.url === "/.well-known/jwks.json") {
      hits++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(jwks));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();
  const issuer = `http://127.0.0.1:${port}`;
  return {
    issuer,
    jwksUrl: `${issuer}/.well-known/jwks.json`,
    hits: () => hits,
    setKeys(nextKeys) {
      jwks = { keys: nextKeys };
    },
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

async function signToken(key, kid, issuer, overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    qid: "qid-123",
    actor: "user",
    initiated_via: "conversation",
    mcp: { tools: ["alpha", "beta"] },
    ...overrides
  };
  const token = new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(issuer)
    .setAudience(overrides.aud ?? APP_SLUG)
    .setSubject(overrides.sub ?? "+15551230000")
    .setJti(overrides.jti ?? randomUUID())
    .setIssuedAt(overrides.iat ?? now)
    .setExpirationTime(overrides.exp ?? now + 300);
  return token.sign(key);
}

const key = await makeKey("test-kid");
const server = await startJwksServer([key.jwk]);

test.after(async () => {
  await server.close();
});

function makeAuthenticator(opts = {}) {
  return new Authenticator({
    appSlug: APP_SLUG,
    issuer: server.issuer,
    jwksUrl: server.jwksUrl,
    enableReplayProtection: opts.replay ?? false,
    replayStore: opts.replay ? new InMemoryReplayStore() : undefined,
    negativeCacheMs: opts.negativeCacheMs ?? 2000
  });
}

test("accepts a valid token and returns context with raw claims", async () => {
  const authenticator = makeAuthenticator();
  const token = await signToken(key.privateKey, key.kid, server.issuer, { autonomous: true });
  const ctx = await authenticator.verifyToken(token, [], true);
  assert.equal(ctx.user.qid, "qid-123");
  assert.equal(ctx.token.aud, APP_SLUG);
  assert.deepEqual(ctx.tools, ["alpha", "beta"]);
  assert.equal(ctx.autonomous, true);
  assert.ok(ctx.raw);
});

test("rejects malformed authorization headers", async () => {
  const authenticator = makeAuthenticator();
  await assert.rejects(() => authenticator.verifyAuthorizationHeader(null), (err) => err.code === "token_missing");
  await assert.rejects(
    () => authenticator.verifyAuthorizationHeader("Token abc"),
    (err) => err.code === "invalid_authorization_header"
  );
});

test("requires requested tools to be present", async () => {
  const authenticator = makeAuthenticator();
  const token = await signToken(key.privateKey, key.kid, server.issuer);
  await assert.rejects(
    () => authenticator.verifyToken(token, ["gamma"]),
    (err) => err instanceof AuthError && err.code === "tool_forbidden"
  );
});

test("prevents replay when enabled", async () => {
  const authenticator = makeAuthenticator({ replay: true });
  const jti = randomUUID();
  const token = await signToken(key.privateKey, key.kid, server.issuer, { jti });
  await authenticator.verifyToken(token);
  await assert.rejects(
    () => authenticator.verifyToken(token),
    (err) => err instanceof AuthError && err.code === "replay_detected"
  );
});

test("rejects issuer and claim problems", async () => {
  const authenticator = makeAuthenticator();
  const tokenWrongIss = await signToken(key.privateKey, key.kid, "http://other");
  await assert.rejects(
    () => authenticator.verifyToken(tokenWrongIss),
    (err) => err instanceof AuthError && err.code === "issuer_mismatch"
  );
  const tokenBadSub = await signToken(key.privateKey, key.kid, server.issuer, { sub: "12345" });
  await assert.rejects(
    () => authenticator.verifyToken(tokenBadSub),
    (err) => err instanceof AuthError && err.code === "invalid_claim"
  );
});

test("handles JWKS reload and negative caching for unknown kid", async () => {
  const authenticator = makeAuthenticator({ negativeCacheMs: 5000 });
  const unknownKid = "missing-kid";
  const token = await signToken(key.privateKey, unknownKid, server.issuer);
  const startHits = server.hits();
  await assert.rejects(
    () => authenticator.verifyToken(token),
    (err) => err instanceof AuthError && err.code === "unknown_kid"
  );
  const afterFirst = server.hits();
  assert.equal(afterFirst - startHits, 2);
  await assert.rejects(
    () => authenticator.verifyToken(token),
    (err) => err instanceof AuthError && err.code === "unknown_kid"
  );
  assert.equal(server.hits(), afterFirst);
});

test("fetches hosted JWKS and exposes test kid", async () => {
  const res = await fetch(HOSTED_JWKS_URL, { headers: { accept: "application/json" } });
  assert.equal(res.ok, true);
  const data = await res.json();
  assert.ok(Array.isArray(data.keys));
  const testKid = "test-kid-cjld2cjxh0000qzrmn831i7rn";
  assert.ok(data.keys.some((k) => k.kid === testKid));
  const selector = createLocalJWKSet(data);
  const key = await selector({ alg: "RS256", kid: testKid }, null);
  assert.ok(key);
});

