CREATE TABLE mfa_accounts (
  user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT,
  totp_last_step INTEGER NOT NULL DEFAULT -1,
  totp_attempts INTEGER NOT NULL DEFAULT 0,
  totp_retry_at INTEGER NOT NULL DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE mfa_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES mfa_accounts(user_id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT
);
--> statement-breakpoint
CREATE INDEX mfa_credentials_user_idx ON mfa_credentials(user_id);
--> statement-breakpoint
CREATE TABLE mfa_recovery_codes (
  hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES mfa_accounts(user_id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX mfa_recovery_codes_user_idx ON mfa_recovery_codes(user_id);
--> statement-breakpoint
CREATE TABLE mfa_pending (
  token_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES mfa_accounts(user_id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  revision INTEGER NOT NULL,
  purpose TEXT NOT NULL,
  replace_factors INTEGER NOT NULL DEFAULT 0,
  initial_setup INTEGER NOT NULL DEFAULT 0,
  next TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  challenge TEXT,
  totp_secret TEXT,
  recovery_hash TEXT,
  marker TEXT
);
--> statement-breakpoint
CREATE INDEX mfa_pending_expiry_idx ON mfa_pending(expires_at);
--> statement-breakpoint
CREATE INDEX mfa_pending_user_idx ON mfa_pending(user_id);
