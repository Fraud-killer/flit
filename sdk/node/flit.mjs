/**
 * FLIT server-side client.
 *
 * Signs requests the way core.auth.handlers.hmac_authentication verifies
 * them. The signature covers the method, path, body, timestamp and content
 * type, so a signed request cannot be replayed against a different endpoint.
 *
 * The subtlety worth knowing is the body hash. It is taken over *canonical*
 * JSON: keys sorted, no whitespace, and non-ASCII escaped, because Python's
 * json.dumps escapes non-ASCII by default and JavaScript's JSON.stringify
 * does not. One accented character in a name field is enough to produce a
 * signature the server rejects, and the failure looks like a credentials
 * problem rather than an encoding one. sdk/node/test/parity.mjs checks this
 * implementation against the Python one, including that case.
 */

import { createHash, createHmac, randomBytes } from "node:crypto";

const NON_ASCII = /[\u0080-\uFFFF]/g;

function escapeNonAscii(text) {
  return text.replace(
    NON_ASCII,
    (character) => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

/** Equivalent to Python's json.dumps(value, sort_keys=True, separators=(",", ":")). */
export function canonicalJson(value) {
  if (value === null || value === undefined) return "null";

  const type = typeof value;

  if (type === "boolean") return value ? "true" : "false";
  if (type === "number") return JSON.stringify(value);
  if (type === "string") return escapeNonAscii(JSON.stringify(value));

  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }

  const pairs = Object.keys(value)
    .sort()
    .map(
      (key) =>
        escapeNonAscii(JSON.stringify(key)) + ":" + canonicalJson(value[key]),
    );

  return "{" + pairs.join(",") + "}";
}

/** Equivalent to devkit.create_hash_value: sha256 of the base64 of canonical JSON. */
export function hashValue(value) {
  const base64 = Buffer.from(canonicalJson(value), "utf8").toString("base64");
  return createHash("sha256").update(base64).digest("hex");
}

export function signature({
  applicationId,
  secretKey,
  method,
  path,
  body,
  timestamp,
  contentType = "application/json",
}) {
  const messageHash = hashValue({
    body_hash: hashValue(body),
    content_type: contentType,
    method: method.toLowerCase(),
    path: path.toLowerCase(),
    timestamp,
  });

  const digest = createHmac("sha256", secretKey)
    .update(messageHash)
    .digest("hex");

  return "HMAC-SHA256 " + applicationId + ":" + digest;
}

export class Flit {
  /**
   * `timeoutMs` is short on purpose. A fraud decision that has not arrived is
   * not a reason to fail a customer's signup — see `failOpen`.
   */
  constructor({ baseUrl, applicationId, secretKey, timeoutMs = 2000 }) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.applicationId = applicationId;
    this.secretKey = secretKey;
    this.timeoutMs = timeoutMs;
  }

  async post(path, body) {
    // Seconds, not milliseconds. The replay-protection middleware compares
    // this against its own clock in seconds, so Date.now() lands roughly
    // fifty thousand years in the future and every request is rejected as a
    // replay. Signature parity tests cannot catch this: they pin a fixed
    // timestamp, so both sides agree on the same wrong value.
    const timestamp = String(Math.floor(Date.now() / 1000));

    // Replay protection also requires a nonce, unique per application and
    // between 16 and 64 characters. It is remembered server-side for the
    // tolerance window, so it must be fresh on every request.
    const nonce = randomBytes(16).toString("hex");

    const response = await fetch(this.baseUrl + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        Authorization: signature({
          applicationId: this.applicationId,
          secretKey: this.secretKey,
          method: "POST",
          path,
          body,
          timestamp,
        }),
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    return response.json();
  }

  auditRegistration(event) {
    return this.post(
      "/api/v1/applications/" + this.applicationId + "/audit-registration",
      event,
    );
  }

  auditTransaction(event) {
    return this.post(
      "/api/v1/applications/" + this.applicationId + "/audit-transaction",
      event,
    );
  }

  /**
   * A credential action: `login`, `login_failed`, `password_reset_requested`,
   * `password_reset_completed`, `password_change`, `email_change`,
   * `phone_change`, `two_factor_enabled`, `two_factor_disabled` or
   * `new_device_login`.
   *
   * Report the reset request and the login separately, as they happen. The
   * takeover rules read the interval between them, and an integration that
   * only reports the login has thrown away the one number that catches it.
   */
  auditAuthentication(event) {
    return this.post(
      "/api/v1/applications/" + this.applicationId + "/audit-authentication",
      event,
    );
  }

  reportOutcome(outcome) {
    return this.post(
      "/api/v1/applications/" + this.applicationId + "/outcomes",
      outcome,
    );
  }
}

/**
 * Run a decision without letting it break the flow it is advising on.
 *
 * FLIT being slow, down or misconfigured must never stop a real customer
 * signing up. Every call site should go through this: on any failure the
 * decision comes back inert — nothing blocked, nothing challenged — and the
 * caller carries on.
 */
export async function failOpen(promise, onError = () => {}) {
  try {
    const body = await promise;
    return (body && body.data) || inert();
  } catch (error) {
    onError(error);
    return inert();
  }
}

function inert() {
  return {
    should_block: false,
    should_challenge: false,
    should_review: false,
    unavailable: true,
  };
}
