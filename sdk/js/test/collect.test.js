import test from "node:test";
import assert from "node:assert/strict";

import { collect, FlitError } from "../src/index.js";

function fakeResponse(body, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => body };
}

function context({ deviceKey = null, failStorage = false } = {}) {
  const store = new Map();
  if (deviceKey) store.set("flit.device_key", deviceKey);

  return {
    crypto: globalThis.crypto,
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    localStorage: {
      getItem: (key) => (failStorage ? (() => { throw new Error("blocked"); })() : store.get(key) ?? null),
      setItem: (key, value) => {
        if (failStorage) throw new Error("blocked");
        store.set(key, value);
      },
    },
    store,
  };
}

const SIGNALS = { platform: "MacIntel", canvas: "abc" };

test("posts signals and returns the visit token", async () => {
  const calls = [];
  const ctx = context();

  const result = await collect({
    key: "flit_pk_test",
    endpoint: "https://api.example.com/api/v1/collect",
    context: ctx,
    signals: SIGNALS,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return fakeResponse({
        data: { visit_token: "vt_123", device_key: "flit_dk_1", expires_in: 1800 },
      });
    },
  });

  assert.deepEqual(result, { visitToken: "vt_123", deviceKey: "flit_dk_1", expiresIn: 1800 });

  const [call] = calls;
  assert.equal(call.url, "https://api.example.com/api/v1/collect");
  assert.equal(call.options.method, "POST");
  assert.equal(call.options.credentials, "omit");

  const body = JSON.parse(call.options.body);
  assert.equal(body.key, "flit_pk_test");
  assert.equal(body.device_key, null);
  assert.deepEqual(body.signals, SIGNALS);

  // The issued key is kept for the next visit.
  assert.equal(ctx.store.get("flit.device_key"), "flit_dk_1");
});

test("returns a stored device key on later visits", async () => {
  let sent = null;

  await collect({
    key: "flit_pk_test",
    context: context({ deviceKey: "flit_dk_known" }),
    signals: SIGNALS,
    fetchImpl: async (url, options) => {
      sent = JSON.parse(options.body).device_key;
      return fakeResponse({ data: { visit_token: "vt", device_key: "flit_dk_known" } });
    },
  });

  assert.equal(sent, "flit_dk_known");
});

test("works when storage is blocked", async () => {
  const result = await collect({
    key: "flit_pk_test",
    context: context({ failStorage: true }),
    signals: SIGNALS,
    fetchImpl: async () => fakeResponse({ data: { visit_token: "vt", device_key: "flit_dk_1" } }),
  });

  assert.equal(result.visitToken, "vt");
});

test("surfaces server errors", async () => {
  await assert.rejects(
    collect({
      key: "flit_pk_bad",
      context: context(),
      signals: SIGNALS,
      fetchImpl: async () => fakeResponse(
        { data: null, errors: [{ code: "collect_key_exist", text: "Must be a valid collection key for an application" }] },
        { ok: false, status: 400 },
      ),
    }),
    (error) => error instanceof FlitError && /valid collection key/.test(error.message),
  );
});

test("requires a collection key", async () => {
  await assert.rejects(
    collect({ context: context(), signals: SIGNALS, fetchImpl: async () => fakeResponse({}) }),
    (error) => error instanceof FlitError && /key is required/.test(error.message),
  );
});

test("gives up rather than hanging", async () => {
  await assert.rejects(
    collect({
      key: "flit_pk_test",
      context: context(),
      signals: SIGNALS,
      timeoutMs: 10,
      fetchImpl: () => new Promise(() => {}),
    }),
    (error) => error instanceof FlitError && /timed out/.test(error.message),
  );
});
