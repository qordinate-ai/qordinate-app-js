import { createLocalJWKSet, type JWK, type JWTVerifyGetKey } from "jose";
import { JWKSInvalid, JWKSNoMatchingKey } from "jose/errors";
import { AuthError } from "./errors.js";

type Jwks = { keys: JWK[] };

export class JwksManager {
  private jwks?: Jwks;
  private selector?: JWTVerifyGetKey;
  private fetchPromise?: Promise<void>;
  private readonly negative = new Map<string, number>();
  private readonly negativeCacheMs: number;

  constructor(private readonly jwksUrl: string, negativeCacheMs = 30_000) {
    this.negativeCacheMs = negativeCacheMs;
  }

  readonly getKey: JWTVerifyGetKey = async (protectedHeader, token) => {
    const kid = protectedHeader.kid;
    if (!kid) throw new AuthError(401, "unknown_kid", "Missing key id");

    const now = Date.now();
    const blockedUntil = this.negative.get(kid);
    if (blockedUntil && blockedUntil > now) {
      throw new AuthError(401, "unknown_kid", "Unknown signing key");
    }

    await this.ensureLoaded();
    try {
      return await this.selector!(protectedHeader, token);
    } catch (err) {
      if (err instanceof JWKSNoMatchingKey) {
        await this.reload();
        try {
          return await this.selector!(protectedHeader, token);
        } catch (errRetry) {
          if (errRetry instanceof JWKSNoMatchingKey) {
            this.negative.set(kid, now + this.negativeCacheMs);
            throw new AuthError(401, "unknown_kid", "Unknown signing key");
          }
          throw this.toAuthError(errRetry);
        }
      }
      throw this.toAuthError(err);
    }
  };

  private async ensureLoaded(): Promise<void> {
    if (this.selector) return;
    await this.reload();
  }

  private async reload(): Promise<void> {
    if (!this.fetchPromise) this.fetchPromise = this.fetchJwks();
    try {
      await this.fetchPromise;
    } finally {
      this.fetchPromise = undefined;
    }
  }

  private async fetchJwks(): Promise<void> {
    const res = await fetch(this.jwksUrl, { headers: { accept: "application/json" } });
    if (!res.ok) throw new AuthError(500, "server_error", "Failed to fetch JWKS");
    const data = (await res.json()) as unknown;
    if (!this.isValidJwks(data)) {
      throw new AuthError(500, "server_error", "Invalid JWKS response");
    }
    this.jwks = data;
    this.selector = createLocalJWKSet(data as unknown as Parameters<typeof createLocalJWKSet>[0]);
  }

  private isValidJwks(data: unknown): data is Jwks {
    return !!data && typeof data === "object" && Array.isArray((data as Jwks).keys);
  }

  private toAuthError(err: unknown): AuthError {
    if (err instanceof AuthError) return err;
    if (err instanceof JWKSInvalid) return new AuthError(500, "server_error", "Invalid JWKS");
    return new AuthError(401, "invalid_signature", "Token signature could not be verified");
  }
}

