/**
 * Remembers the device key FLIT issued. Storage can throw (private windows,
 * blocked site data), so every access is guarded and failure is not fatal:
 * without a key the server still identifies the device from its signals.
 */

const STORAGE_KEY = "flit.device_key";

export function readDeviceKey(context = globalThis) {
  try {
    return context.localStorage?.getItem(STORAGE_KEY) || null;
  } catch {
    return null;
  }
}

export function writeDeviceKey(deviceKey, context = globalThis) {
  if (!deviceKey) return false;

  try {
    context.localStorage?.setItem(STORAGE_KEY, deviceKey);
    return true;
  } catch {
    return false;
  }
}
