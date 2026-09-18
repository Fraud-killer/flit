/**
 * FLIT browser SDK.
 *
 * Collects device signals and exchanges them for a short-lived visit token:
 *
 *   import { collect } from "@flit/browser";
 *   const { visitToken } = await collect({ key: "flit_pk_..." });
 *
 * Send that token to your own server and include it as `visit_token` when
 * you ask FLIT to audit the event. The collection key identifies your
 * application and is safe to ship in a page; it authorises nothing.
 */

import { collectSignals } from "./signals.js";
import { readDeviceKey, writeDeviceKey } from "./storage.js";

const DEFAULT_ENDPOINT = "https://api.flit.io/api/v1/collect";

export class FlitError extends Error {}

export async function collect({
  key,
  endpoint = DEFAULT_ENDPOINT,
  context = globalThis,
  fetchImpl = context.fetch ? context.fetch.bind(context) : undefined,
  timeoutMs = 5000,
  signals: providedSignals,
} = {}) {
  if (!key) throw new FlitError("A collection key is required");
  if (!fetchImpl) throw new FlitError("fetch is unavailable in this environment");

  const signals = providedSignals ?? (await collectSignals(context));
  const deviceKey = readDeviceKey(context);

  const response = await withTimeout(
    fetchImpl(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, signals, device_key: deviceKey }),
      // The token is the credential; no cookies are sent or needed.
      credentials: "omit",
      mode: "cors",
    }),
    timeoutMs,
    context,
  );

  const payload = await response.json();

  if (!response.ok || !payload?.data?.visit_token) {
    const [error] = payload?.errors || [];
    throw new FlitError(error?.text || `Collection failed (${response.status})`);
  }

  writeDeviceKey(payload.data.device_key, context);

  return {
    visitToken: payload.data.visit_token,
    deviceKey: payload.data.device_key,
    expiresIn: payload.data.expires_in,
  };
}

function withTimeout(promise, timeoutMs, context) {
  if (!timeoutMs) return promise;

  const timers = context.setTimeout ? context : globalThis;

  return new Promise((resolve, reject) => {
    const timer = timers.setTimeout(
      () => reject(new FlitError("Collection timed out")),
      timeoutMs,
    );

    promise.then(
      (value) => { timers.clearTimeout(timer); resolve(value); },
      (error) => { timers.clearTimeout(timer); reject(error); },
    );
  });
}

export { collectSignals } from "./signals.js";
export { readDeviceKey } from "./storage.js";
