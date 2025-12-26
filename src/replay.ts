export interface ReplayStore {
  exists(jti: string): Promise<boolean> | boolean;
  store(jti: string, ttlSeconds: number): Promise<void> | void;
}

export class InMemoryReplayStore implements ReplayStore {
  private readonly entries = new Map<string, number>();

  constructor(private readonly cleanupIntervalMs = 60_000) {}

  async exists(jti: string): Promise<boolean> {
    this.cleanup();
    const expiresAt = this.entries.get(jti);
    if (!expiresAt) return false;
    if (expiresAt <= Date.now()) {
      this.entries.delete(jti);
      return false;
    }
    return true;
  }

  async store(jti: string, ttlSeconds: number): Promise<void> {
    this.cleanup();
    const expiresAt = Date.now() + ttlSeconds * 1000;
    this.entries.set(jti, expiresAt);
  }

  private cleanup(): void {
    const now = Date.now();
    if (this.entries.size === 0) return;
    for (const [jti, expiresAt] of this.entries.entries()) {
      if (expiresAt <= now) {
        this.entries.delete(jti);
      }
    }
  }
}

