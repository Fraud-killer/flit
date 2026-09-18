import test from "node:test";
import assert from "node:assert/strict";

import { collectSignals, canvasSignal, webglSignals, fontsSignal, pluginNames } from "../src/signals.js";
import { hash, stableStringify, fallbackHash } from "../src/hash.js";
import { readDeviceKey, writeDeviceKey } from "../src/storage.js";

/** A browser context good enough to exercise every collector. */
function fakeContext({ canvasData = "data:image/png;base64,AAAA", renderer = "Apple M2", broken = [] } = {}) {
  const storage = new Map();

  const element = (tag) => {
    if (broken.includes(tag)) throw new Error(`cannot create ${tag}`);

    if (tag === "canvas") {
      return {
        width: 0,
        height: 0,
        getContext: (kind) => {
          if (kind === "2d") {
            return { fillRect() {}, fillText() {} };
          }
          return {
            RENDERER: 1, VENDOR: 2, VERSION: 3, SHADING_LANGUAGE_VERSION: 4,
            MAX_TEXTURE_SIZE: 5, MAX_VIEWPORT_DIMS: 6,
            getExtension: () => ({ UNMASKED_RENDERER_WEBGL: 10, UNMASKED_VENDOR_WEBGL: 11 }),
            getParameter: (name) => (name === 10 ? renderer : `param_${name}`),
            getSupportedExtensions: () => ["EXT_b", "EXT_a"],
          };
        },
        toDataURL: () => canvasData,
      };
    }

    let family = "";
    return {
      style: {
        set fontFamily(value) { family = value; },
        get fontFamily() { return family; },
      },
      textContent: "",
      // Widths differ per family, so some probe fonts count as present.
      get offsetWidth() { return 100 + family.length; },
      get offsetHeight() { return 20; },
    };
  };

  return {
    crypto: globalThis.crypto,
    navigator: {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0",
      userAgentData: { brands: [{ brand: "Chromium", version: "120" }], platform: "macOS" },
      platform: "MacIntel",
      languages: ["en-GB", "en"],
      hardwareConcurrency: 8,
      deviceMemory: 16,
      maxTouchPoints: 0,
      plugins: [{ name: "PDF Viewer" }, { name: "Chrome PDF Viewer" }],
      webdriver: false,
    },
    screen: { width: 1728, height: 1117, colorDepth: 30 },
    devicePixelRatio: 2,
    Intl,
    Date,
    document: { body: { appendChild() {}, removeChild() {} }, createElement: element },
    localStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
    },
  };
}

test("collects a full signal set", async () => {
  const signals = await collectSignals(fakeContext());

  assert.equal(signals.platform, "MacIntel");
  assert.equal(signals.ua_platform, "macOS");
  assert.deepEqual(signals.ua_brands, ["Chromium/120"]);
  assert.deepEqual(signals.languages, ["en-GB", "en"]);
  assert.deepEqual(signals.screen, { width: 1728, height: 1117, color_depth: 30, pixel_ratio: 2 });
  assert.equal(signals.hardware_concurrency, 8);
  assert.equal(signals.webdriver, false);
  assert.equal(signals.webgl_renderer, "Apple M2");
  assert.equal(typeof signals.timezone, "string");
  assert.equal(typeof signals.timezone_offset, "number");

  for (const name of ["canvas", "webgl", "fonts"]) {
    assert.match(signals[name], /^[0-9a-f]{32}$/, `${name} should be a digest`);
  }
});

test("raw signal material never leaves the browser", async () => {
  const canvasData = "data:image/png;base64,SECRET_PIXELS";
  const signals = await collectSignals(fakeContext({ canvasData }));
  const payload = JSON.stringify(signals);

  assert.ok(!payload.includes("SECRET_PIXELS"));
  assert.ok(!payload.includes("Arial"));
});

test("different devices produce different canvas digests", async () => {
  const one = await canvasSignal(fakeContext({ canvasData: "aaa" }));
  const two = await canvasSignal(fakeContext({ canvasData: "bbb" }));

  assert.notEqual(one, two);
  assert.equal(one, await canvasSignal(fakeContext({ canvasData: "aaa" })));
});

test("a collector that throws yields null, not an exception", async () => {
  const signals = await collectSignals(fakeContext({ broken: ["canvas", "span"] }));

  assert.equal(signals.canvas, null);
  assert.equal(signals.webgl, null);
  assert.equal(signals.fonts, null);
  // Everything else is still collected.
  assert.equal(signals.platform, "MacIntel");
});

test("collects nothing but stays intact in a bare context", async () => {
  const signals = await collectSignals({});

  assert.equal(signals.user_agent, null);
  assert.equal(signals.canvas, null);
  assert.deepEqual(signals.plugins, []);
  assert.equal(signals.webdriver, false);
});

test("webgl reports the unmasked renderer for spoofing checks", async () => {
  const { webgl_renderer } = await webglSignals(fakeContext({ renderer: "Google SwiftShader" }));

  assert.equal(webgl_renderer, "Google SwiftShader");
});

test("plugin names are sorted so ordering does not change the digest", () => {
  assert.deepEqual(pluginNames(fakeContext()), ["Chrome PDF Viewer", "PDF Viewer"]);
});

test("font probing cleans up the element it measures", async () => {
  let appended = 0;
  let removed = 0;
  const context = fakeContext();
  context.document.body.appendChild = () => { appended += 1; };
  context.document.body.removeChild = () => { removed += 1; };

  await fontsSignal(context);

  assert.equal(appended, 1);
  assert.equal(removed, 1);
});

test("hashing is stable regardless of key order", async () => {
  const one = await hash({ a: 1, b: [2, 3] });
  const two = await hash({ b: [2, 3], a: 1 });

  assert.equal(one, two);
  assert.equal(stableStringify({ b: 1, a: 2 }), '{"a":2,"b":1}');
});

test("hashing falls back when SubtleCrypto is unavailable", async () => {
  const digest = await hash("value", { crypto: undefined });

  assert.match(digest, /^f_[0-9a-f]{8}$/);
  assert.notEqual(fallbackHash("value"), fallbackHash("other"));
});

test("device key round-trips through storage", () => {
  const context = fakeContext();

  assert.equal(readDeviceKey(context), null);
  assert.equal(writeDeviceKey("flit_dk_abc", context), true);
  assert.equal(readDeviceKey(context), "flit_dk_abc");
});

test("storage failures are survivable", () => {
  const context = {
    localStorage: {
      getItem() { throw new Error("blocked"); },
      setItem() { throw new Error("blocked"); },
    },
  };

  assert.equal(readDeviceKey(context), null);
  assert.equal(writeDeviceKey("flit_dk_abc", context), false);
});
