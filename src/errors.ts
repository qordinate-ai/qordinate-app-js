export type AuthErrorCode =
  | "token_missing"
  | "invalid_authorization_header"
  | "invalid_signature"
  | "issuer_mismatch"
  | "audience_mismatch"
  | "token_expired"
  | "invalid_claim"
  | "tool_forbidden"
  | "replay_detected"
  | "unknown_kid"
  | "server_error";

export class AuthError extends Error {
  readonly status: number;
  readonly code: AuthErrorCode;

  constructor(status: number, code: AuthErrorCode, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

