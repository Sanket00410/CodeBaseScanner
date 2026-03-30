import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";

export interface ToolManagerAuthConfig {
  enabled: boolean;
  allowedEmailMasked: string;
  authMode: "totp_only" | "smtp_otp_mfa";
  otpRequired: boolean;
  otpTtlSeconds: number;
  sessionTtlSeconds: number;
  mfaRequired: boolean;
  mfaIssuer: string;
  smtpConfigured: boolean;
  sessionValid: boolean;
  sessionEmail?: string;
  sessionExpiresAt?: string;
  message: string;
}

export interface ToolManagerOtpResult {
  success: boolean;
  message: string;
  expiresInSeconds?: number;
}

export interface ToolManagerVerifyResult {
  success: boolean;
  message: string;
  authToken?: string;
  expiresAt?: string;
  email?: string;
}

interface PendingOtp {
  email: string;
  otpHash: string;
  expiresAtMs: number;
  attempts: number;
  issuedAtMs: number;
}

interface SessionState {
  email: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export class ToolAccessAuthService {
  private readonly authMode: "totp_only" | "smtp_otp_mfa";
  private readonly enabled: boolean;
  private readonly allowedEmail: string;
  private readonly otpTtlSeconds: number;
  private readonly sessionTtlSeconds: number;
  private readonly maxOtpAttempts: number;
  private readonly mfaRequired: boolean;
  private readonly mfaSecret: string;
  private readonly mfaIssuer: string;
  private readonly smtpConfigured: boolean;

  private pendingOtp: PendingOtp | null = null;
  private readonly sessions = new Map<string, SessionState>();

  constructor() {
    this.authMode = parseAuthMode(process.env.CODESENTINELX_TOOLMANAGER_AUTH_MODE);
    this.allowedEmail = normalizeEmail(process.env.CODESENTINELX_TOOLMANAGER_ALLOWED_EMAIL || "");
    const ownerLockMode = String(process.env.CODESENTINELX_TOOLMANAGER_OWNER_LOCK || "")
      .trim()
      .toLowerCase();
    const ownerLockEnabled = ownerLockMode === "1" || ownerLockMode === "true" || ownerLockMode === "yes";
    this.enabled = ownerLockEnabled && this.allowedEmail.length > 0;
    this.otpTtlSeconds = clampInt(process.env.CODESENTINELX_TOOLMANAGER_OTP_TTL_SECONDS, 300, 60, 900);
    this.sessionTtlSeconds = clampInt(process.env.CODESENTINELX_TOOLMANAGER_SESSION_TTL_SECONDS, 3600, 600, 28800);
    this.maxOtpAttempts = clampInt(process.env.CODESENTINELX_TOOLMANAGER_MAX_OTP_ATTEMPTS, 5, 3, 10);
    this.mfaSecret = String(process.env.CODESENTINELX_TOOLMANAGER_MFA_SECRET || "").trim();
    this.mfaRequired = this.mfaSecret.length > 0 || this.authMode === "totp_only";
    this.mfaIssuer = String(process.env.CODESENTINELX_TOOLMANAGER_MFA_ISSUER || "CodeSentinelX").trim() || "CodeSentinelX";

    const smtpHost = String(process.env.CODESENTINELX_SMTP_HOST || "").trim();
    const smtpFrom = String(process.env.CODESENTINELX_SMTP_FROM || "").trim();
    this.smtpConfigured = smtpHost.length > 0 && smtpFrom.length > 0;
  }

  getConfig(sessionToken?: string): ToolManagerAuthConfig {
    this.cleanupExpiredState();
    const session = sessionToken ? this.sessions.get(sessionToken) : undefined;
    const sessionValid = Boolean(session && session.expiresAtMs > Date.now());

    let message = "Tool Manager access is role-governed.";
    if (!this.enabled) {
      message =
        "Owner login is disabled. Set CODESENTINELX_TOOLMANAGER_OWNER_LOCK=1 and CODESENTINELX_TOOLMANAGER_ALLOWED_EMAIL to enable it.";
    } else if (this.authMode === "totp_only") {
      if (!this.mfaSecret) {
        message = "TOTP-only mode is enabled, but MFA secret is missing. Set CODESENTINELX_TOOLMANAGER_MFA_SECRET.";
      } else {
        message = "TOTP-only owner login is enabled. Enter owner email and authenticator code.";
      }
    } else if (!this.smtpConfigured) {
      message = "SMTP mode is enabled, but SMTP is not configured. Configure CODESENTINELX_SMTP_* variables.";
    } else if (this.mfaSecret) {
      message = "OTP + MFA is required for Tool Manager access.";
    } else {
      message = "OTP is required for Tool Manager access.";
    }

    return {
      enabled: this.enabled,
      allowedEmailMasked: this.enabled ? maskEmail(this.allowedEmail) : "",
      authMode: this.authMode,
      otpRequired: this.authMode !== "totp_only",
      otpTtlSeconds: this.otpTtlSeconds,
      sessionTtlSeconds: this.sessionTtlSeconds,
      mfaRequired: this.mfaRequired,
      mfaIssuer: this.mfaIssuer,
      smtpConfigured: this.smtpConfigured,
      sessionValid,
      sessionEmail: sessionValid && session ? maskEmail(session.email) : "",
      sessionExpiresAt: sessionValid && session ? new Date(session.expiresAtMs).toISOString() : "",
      message,
    };
  }

  async requestOtp(emailInput: string): Promise<ToolManagerOtpResult> {
    this.cleanupExpiredState();

    if (!this.enabled) {
      return {
        success: false,
        message: "Tool Manager owner lock is not enabled. Configure allowed email first.",
      };
    }

    if (this.authMode === "totp_only") {
      const normalizedTotp = normalizeEmail(emailInput);
      if (!normalizedTotp || normalizedTotp !== this.allowedEmail) {
        return {
          success: false,
          message: "Access denied. Only the configured owner email is allowed.",
        };
      }
      if (!this.mfaSecret) {
        return {
          success: false,
          message: "MFA secret is missing. Set CODESENTINELX_TOOLMANAGER_MFA_SECRET.",
        };
      }
      return {
        success: true,
        message: "OTP step is disabled in TOTP-only mode. Enter your authenticator code and verify.",
        expiresInSeconds: this.otpTtlSeconds,
      };
    }

    if (!this.smtpConfigured) {
      return {
        success: false,
        message: "SMTP is not configured for OTP delivery. Configure CODESENTINELX_SMTP_* variables.",
      };
    }

    const normalized = normalizeEmail(emailInput);
    if (!normalized || normalized !== this.allowedEmail) {
      return {
        success: false,
        message: "Access denied. Only the configured owner email is allowed.",
      };
    }

    const otp = String(randomInt(0, 1_000_000)).padStart(6, "0");
    const now = Date.now();
    this.pendingOtp = {
      email: normalized,
      otpHash: hashOtp(otp),
      expiresAtMs: now + this.otpTtlSeconds * 1000,
      attempts: 0,
      issuedAtMs: now,
    };

    await sendOtpEmail({
      to: normalized,
      otp,
      issuer: this.mfaIssuer,
      ttlSeconds: this.otpTtlSeconds,
    });

    return {
      success: true,
      message: `OTP sent to ${maskEmail(normalized)}.`,
      expiresInSeconds: this.otpTtlSeconds,
    };
  }

  verifyAccess(emailInput: string, otpInput: string, mfaCodeInput?: string): ToolManagerVerifyResult {
    this.cleanupExpiredState();

    if (!this.enabled) {
      return {
        success: false,
        message: "Tool Manager owner lock is not enabled.",
      };
    }

    const normalized = normalizeEmail(emailInput);
    if (!normalized || normalized !== this.allowedEmail) {
      return {
        success: false,
        message: "Access denied. Only the configured owner email is allowed.",
      };
    }

    if (this.authMode === "totp_only") {
      if (!this.mfaSecret) {
        return {
          success: false,
          message: "MFA secret is missing. Set CODESENTINELX_TOOLMANAGER_MFA_SECRET.",
        };
      }
      const mfaCode = String(mfaCodeInput || "").trim();
      if (!verifyTotpCode(this.mfaSecret, mfaCode)) {
        return {
          success: false,
          message: "Invalid MFA code.",
        };
      }

      const token = randomBytes(32).toString("hex");
      const now = Date.now();
      const expiresAtMs = now + this.sessionTtlSeconds * 1000;
      this.sessions.set(token, {
        email: normalized,
        issuedAtMs: now,
        expiresAtMs,
      });

      return {
        success: true,
        message: "Tool Manager access granted.",
        authToken: token,
        expiresAt: new Date(expiresAtMs).toISOString(),
        email: maskEmail(normalized),
      };
    }

    if (!this.pendingOtp || this.pendingOtp.email !== normalized) {
      return {
        success: false,
        message: "No active OTP challenge for this email. Request OTP again.",
      };
    }

    if (this.pendingOtp.expiresAtMs <= Date.now()) {
      this.pendingOtp = null;
      return {
        success: false,
        message: "OTP expired. Request a new OTP.",
      };
    }

    if (this.pendingOtp.attempts >= this.maxOtpAttempts) {
      this.pendingOtp = null;
      return {
        success: false,
        message: "Maximum OTP attempts exceeded. Request a new OTP.",
      };
    }

    this.pendingOtp.attempts += 1;
    if (!timingSafeEqualString(this.pendingOtp.otpHash, hashOtp(String(otpInput || "").trim()))) {
      const remaining = Math.max(0, this.maxOtpAttempts - this.pendingOtp.attempts);
      return {
        success: false,
        message: remaining > 0 ? `Invalid OTP. ${remaining} attempt(s) remaining.` : "Invalid OTP. Request a new OTP.",
      };
    }

    if (this.mfaSecret) {
      const mfaCode = String(mfaCodeInput || "").trim();
      if (!verifyTotpCode(this.mfaSecret, mfaCode)) {
        return {
          success: false,
          message: "Invalid MFA code.",
        };
      }
    }

    this.pendingOtp = null;
    const token = randomBytes(32).toString("hex");
    const now = Date.now();
    const expiresAtMs = now + this.sessionTtlSeconds * 1000;
    this.sessions.set(token, {
      email: normalized,
      issuedAtMs: now,
      expiresAtMs,
    });

    return {
      success: true,
      message: "Tool Manager access granted.",
      authToken: token,
      expiresAt: new Date(expiresAtMs).toISOString(),
      email: maskEmail(normalized),
    };
  }

  revokeSession(token: string): { success: boolean; message: string } {
    if (!token) {
      return { success: false, message: "No session token provided." };
    }
    const removed = this.sessions.delete(token);
    return {
      success: removed,
      message: removed ? "Tool Manager session ended." : "Session token was not active.",
    };
  }

  assertAuthorized(token: string | undefined | null): SessionState {
    if (!this.enabled) {
      return {
        email: "owner-lock-disabled",
        issuedAtMs: Date.now(),
        expiresAtMs: Date.now() + 60_000,
      };
    }

    this.cleanupExpiredState();

    if (!token) {
      throw new Error("Tool Manager access denied. Owner authentication session is required.");
    }

    const session = this.sessions.get(token);
    if (!session || session.expiresAtMs <= Date.now()) {
      this.sessions.delete(token);
      throw new Error("Tool Manager session expired. Re-authenticate as owner.");
    }

    if (normalizeEmail(session.email) !== this.allowedEmail) {
      this.sessions.delete(token);
      throw new Error("Tool Manager access denied for this session.");
    }

    return session;
  }

  private cleanupExpiredState(): void {
    const now = Date.now();
    if (this.pendingOtp && this.pendingOtp.expiresAtMs <= now) {
      this.pendingOtp = null;
    }

    for (const [token, session] of this.sessions.entries()) {
      if (session.expiresAtMs <= now) {
        this.sessions.delete(token);
      }
    }
  }
}

function normalizeEmail(value: string): string {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function maskEmail(value: string): string {
  const email = normalizeEmail(value);
  if (!email.includes("@")) {
    return "";
  }
  const [local, domain] = email.split("@", 2);
  if (!local || !domain) {
    return "";
  }
  const first = local.slice(0, 2);
  return `${first}${"*".repeat(Math.max(2, local.length - first.length))}@${domain}`;
}

function clampInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(String(raw || ""), 10);
  if (Number.isNaN(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
}

function parseAuthMode(raw: string | undefined): "totp_only" | "smtp_otp_mfa" {
  const normalized = String(raw || "totp_only").trim().toLowerCase();
  if (normalized === "smtp_otp_mfa" || normalized === "smtp") {
    return "smtp_otp_mfa";
  }
  return "totp_only";
}

function hashOtp(value: string): string {
  return createHash("sha256").update(String(value || "")).digest("hex");
}

function timingSafeEqualString(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf-8");
  const right = Buffer.from(b, "utf-8");
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

async function sendOtpEmail(params: { to: string; otp: string; issuer: string; ttlSeconds: number }): Promise<void> {
  const nodemailerModule = await import("nodemailer");
  const nodemailer = (nodemailerModule.default || nodemailerModule) as {
    createTransport: (options: Record<string, unknown>) => {
      sendMail: (mail: Record<string, unknown>) => Promise<unknown>;
    };
  };

  const host = String(process.env.CODESENTINELX_SMTP_HOST || "").trim();
  const port = Number.parseInt(String(process.env.CODESENTINELX_SMTP_PORT || "587"), 10) || 587;
  const secure = String(process.env.CODESENTINELX_SMTP_SECURE || "false").toLowerCase() === "true";
  const user = String(process.env.CODESENTINELX_SMTP_USER || "").trim();
  const pass = String(process.env.CODESENTINELX_SMTP_PASS || "").trim();
  const from = String(process.env.CODESENTINELX_SMTP_FROM || "").trim();

  if (!host || !from) {
    throw new Error("SMTP settings are incomplete.");
  }

  const transport = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: user && pass ? { user, pass } : undefined,
    connectionTimeout: 15000,
    socketTimeout: 15000,
  });

  const subject = `${params.issuer} Tool Manager OTP`;
  const text = [
    `${params.issuer} Tool Manager Verification`,
    "",
    `Your one-time code is: ${params.otp}`,
    `This code expires in ${params.ttlSeconds} seconds.`,
    "If you did not request this, ignore this email.",
  ].join("\n");

  const html = `
    <div style="font-family:Segoe UI,Arial,sans-serif;line-height:1.4;color:#10253f">
      <h2 style="margin:0 0 8px">${escapeHtml(params.issuer)} Tool Manager Verification</h2>
      <p style="margin:0 0 8px">Your one-time code is:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:4px;margin:6px 0 10px">${escapeHtml(params.otp)}</div>
      <p style="margin:0 0 8px">This code expires in ${params.ttlSeconds} seconds.</p>
      <p style="margin:0;color:#5b7186">If you did not request this, ignore this email.</p>
    </div>
  `;

  await transport.sendMail({
    from,
    to: params.to,
    subject,
    text,
    html,
  });
}

function escapeHtml(value: string): string {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function verifyTotpCode(secretInput: string, codeInput: string): boolean {
  const code = String(codeInput || "").trim();
  if (!/^\d{6}$/.test(code)) {
    return false;
  }

  const secret = decodeTotpSecret(secretInput);
  if (secret.length === 0) {
    return false;
  }

  const window = clampInt(process.env.CODESENTINELX_TOOLMANAGER_MFA_WINDOW, 1, 0, 3);
  const step = 30;
  const nowCounter = Math.floor(Date.now() / 1000 / step);

  for (let offset = -window; offset <= window; offset += 1) {
    const token = generateHotp(secret, nowCounter + offset);
    if (token === code) {
      return true;
    }
  }
  return false;
}

function decodeTotpSecret(input: string): Buffer {
  const raw = String(input || "").trim();
  if (!raw) {
    return Buffer.alloc(0);
  }

  const normalized = raw.replace(/\s+/g, "").replace(/=+$/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(normalized)) {
    return Buffer.from(raw, "utf-8");
  }

  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of normalized) {
    const index = alphabet.indexOf(char);
    if (index < 0) {
      return Buffer.from(raw, "utf-8");
    }
    bits += index.toString(2).padStart(5, "0");
  }

  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateHotp(secret: Buffer, counter: number): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(Math.floor(counter / 0x1_0000_0000), 0);
  counterBuffer.writeUInt32BE(counter & 0xffff_ffff, 4);

  const digest = createHmac("sha1", secret).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const token = binary % 1_000_000;
  return String(token).padStart(6, "0");
}
