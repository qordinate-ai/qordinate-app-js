import { jwtVerify, type JWTPayload } from "jose";
import { AuthError } from "./errors.js";
import { JwksManager } from "./jwks.js";
import type { ReplayStore } from "./replay.js";

type Actor = "user" | "qordinate-agent";
type InitiatedVia = "conversation" | "proactive";

const DEFAULT_ISSUER = "https://auth.qordinate.ai";

export interface AuthConfig {
  appSlug: string;
  issuer?: string;
  jwksUrl?: string;
  replayStore?: ReplayStore;
  enableReplayProtection?: boolean;
  negativeCacheMs?: number;
}

export interface AuthContext {
  user: {
    qid: string;
    phone: string;
  };
  actor: Actor;
  initiated_via: InitiatedVia;
  autonomous?: boolean;
  tools: string[];
  token: {
    iss: string;
    aud: string;
    jti: string;
    exp: number;
    iat: number;
    sub: string;
    qid: string;
  };
  raw?: JWTPayload;
}

export interface VerifyOptions {
  requiredTools?: string[];
  includeRawClaims?: boolean;
}

const ALLOWED_ALGS = ["RS256", "ES256"] as const;
const E164_REGEX = /^\+[1-9]\d{1,14}$/;

export class Authenticator {
  private readonly jwks: JwksManager;
  private readonly replayStore?: ReplayStore;
  private readonly issuer: string;
  private readonly appSlug: string;
  private readonly replayProtectionEnabled: boolean;
  private warnedReplayProtectionOff = false;

  constructor(config: AuthConfig) {
    if (!config.appSlug) throw new AuthError(500, "server_error", "appSlug is required");
    const issuer = config.issuer ?? DEFAULT_ISSUER;
    if (!issuer) throw new AuthError(500, "server_error", "issuer is required");
    this.appSlug = config.appSlug;
    this.issuer = issuer;
    this.replayProtectionEnabled = config.enableReplayProtection ?? false;
    const jwksUrl = config.jwksUrl ?? `${trimTrailingSlash(issuer)}/.well-known/jwks.json`;
    this.jwks = new JwksManager(jwksUrl, config.negativeCacheMs);
    this.replayStore = config.replayStore;
    if (this.replayProtectionEnabled && !this.replayStore) {
      throw new AuthError(500, "server_error", "Replay store is required when replay protection is enabled");
    }
  }

  async verifyAuthorizationHeader(authHeader: string | null | undefined, options?: VerifyOptions): Promise<AuthContext> {
    if (!authHeader) throw new AuthError(401, "token_missing", "Authorization header missing");
    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!match) throw new AuthError(401, "invalid_authorization_header", "Authorization header must be Bearer token");
    const token = match[1];
    return this.verifyToken(token, options?.requiredTools ?? [], options?.includeRawClaims ?? false);
  }

  async verifyToken(token: string, requiredTools: string[] = [], includeRaw = false): Promise<AuthContext> {
    const now = Math.floor(Date.now() / 1000);
    let payload: JWTPayload;

    try {
      ({ payload } = await jwtVerify(token, this.jwks.getKey, {
        algorithms: ALLOWED_ALGS as unknown as string[]
      }));
    } catch (err) {
      throw mapJwtError(err);
    }

    const iss = ensureString(payload.iss, "iss");
    if (iss !== this.issuer) throw new AuthError(401, "issuer_mismatch", "Issuer mismatch");

    const aud = ensureString(payload.aud, "aud");
    if (aud !== this.appSlug) throw new AuthError(403, "audience_mismatch", "Audience mismatch");

    const exp = ensureNumber(payload.exp, "exp");
    const iat = ensureNumber(payload.iat, "iat");
    if (now >= exp) throw new AuthError(401, "token_expired", "Token expired");
    if (iat > now) throw new AuthError(401, "invalid_claim", "Issued-at is in the future");

    const sub = ensureString(payload.sub, "sub");
    if (!E164_REGEX.test(sub)) throw new AuthError(401, "invalid_claim", "Subject must be E.164 phone");
    const qid = ensureString((payload as Record<string, unknown>).qid, "qid");
    const jti = ensureString(payload.jti, "jti");

    const actor = ensureActor((payload as Record<string, unknown>).actor);
    const initiatedVia = ensureInitiated((payload as Record<string, unknown>).initiated_via);
    const autonomous = (payload as Record<string, unknown>).autonomous;
    if (autonomous !== undefined && typeof autonomous !== "boolean") {
      throw new AuthError(401, "invalid_claim", "autonomous must be boolean when present");
    }

    const declaredTools = extractTools((payload as Record<string, unknown>).mcp);
    const requestedTools = requiredTools ?? [];
    if (requestedTools.some((tool) => !declaredTools.includes(tool))) {
      throw new AuthError(403, "tool_forbidden", "Missing required tool permission");
    }
    const effectiveTools = requestedTools.length > 0 ? requestedTools : declaredTools;

    await this.enforceReplay(jti, exp, iat, now);

    return {
      user: { qid, phone: sub },
      actor,
      initiated_via: initiatedVia,
      autonomous,
      tools: effectiveTools,
      token: { iss, aud, jti, exp, iat, sub, qid },
      raw: includeRaw ? payload : undefined
    };
  }

  private async enforceReplay(jti: string, exp: number, iat: number, now: number): Promise<void> {
    if (!this.replayProtectionEnabled) {
      if (!this.warnedReplayProtectionOff) {
        this.warnedReplayProtectionOff = true;
        console.warn("[qordinate-sdk] Replay protection disabled");
      }
      return;
    }
    const store = this.replayStore;
    if (!store) throw new AuthError(500, "server_error", "Replay store is required when replay protection is enabled");
    const ttl = Math.min(exp - now, exp - iat);
    if (ttl <= 0) throw new AuthError(401, "token_expired", "Token expired");
    const seen = await Promise.resolve(store.exists(jti));
    if (seen) throw new AuthError(409, "replay_detected", "Token already used");
    await Promise.resolve(store.store(jti, ttl));
  }
}

function ensureString(value: unknown, claim: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new AuthError(401, "invalid_claim", `${claim} is required`);
  }
  return value;
}

function ensureNumber(value: unknown, claim: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new AuthError(401, "invalid_claim", `${claim} must be a number`);
  }
  return value;
}

function ensureActor(value: unknown): Actor {
  if (value === "user" || value === "qordinate-agent") return value;
  throw new AuthError(401, "invalid_claim", "actor is invalid");
}

function ensureInitiated(value: unknown): InitiatedVia {
  if (value === "conversation" || value === "proactive") return value;
  throw new AuthError(401, "invalid_claim", "initiated_via is invalid");
}

function extractTools(mcpClaim: unknown): string[] {
  if (!mcpClaim || typeof mcpClaim !== "object") return [];
  const tools = (mcpClaim as Record<string, unknown>).tools;
  if (tools === undefined) return [];
  if (!Array.isArray(tools)) throw new AuthError(401, "invalid_claim", "mcp.tools must be an array");
  for (const tool of tools) {
    if (typeof tool !== "string" || tool.length === 0) {
      throw new AuthError(401, "invalid_claim", "mcp.tools entries must be strings");
    }
  }
  return tools;
}

function trimTrailingSlash(input: string): string {
  return input.endsWith("/") ? input.slice(0, -1) : input;
}

function mapJwtError(err: unknown): AuthError {
  if (err instanceof AuthError) return err;
  const code = (err as { code?: string })?.code;
  if (code === "ERR_JWT_EXPIRED") return new AuthError(401, "token_expired", "Token expired");
  return new AuthError(401, "invalid_signature", "Token verification failed");
}

