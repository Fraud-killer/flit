/**
 * Device signal collection.
 *
 * Every collector takes the browser context explicitly and never throws: a
 * signal that cannot be read is reported as null rather than breaking the
 * page it runs on. Identifying material (canvas images, audio buffers, font
 * measurements) is hashed here, so only digests are sent.
 */

import { hash } from "./hash.js";

const FONT_PROBES = [
  "Arial", "Arial Black", "Calibri", "Cambria", "Comic Sans MS", "Courier New",
  "Georgia", "Helvetica", "Impact", "Lucida Console", "Menlo", "Monaco",
  "Segoe UI", "Tahoma", "Times New Roman", "Trebuchet MS", "Verdana",
  "Roboto", "Ubuntu", "Noto Sans", "DejaVu Sans", "Liberation Sans",
];

const BASELINE_FONTS = ["monospace", "sans-serif", "serif"];

const FONT_TEST_STRING = "mmmmmmmmmmlli";
const FONT_TEST_SIZE = "72px";

async function safely(collect, fallback = null) {
  try {
    const value = await collect();
    return value === undefined ? fallback : value;
  } catch {
    return fallback;
  }
}

export function userAgentData(context) {
  const data = context.navigator?.userAgentData;
  if (!data) return { brands: null, platform: null };

  return {
    brands: (data.brands || []).map((brand) => `${brand.brand}/${brand.version}`).sort(),
    platform: data.platform || null,
  };
}

export function screenSignals(context) {
  const screen = context.screen;
  if (!screen) return null;

  return {
    width: screen.width ?? null,
    height: screen.height ?? null,
    color_depth: screen.colorDepth ?? null,
    pixel_ratio: context.devicePixelRatio ?? null,
  };
}

export function timezoneSignals(context) {
  const resolved = context.Intl?.DateTimeFormat?.().resolvedOptions?.();
  const offset = new (context.Date || Date)().getTimezoneOffset?.();

  return {
    timezone: resolved?.timeZone ?? null,
    timezone_offset: typeof offset === "number" ? offset : null,
  };
}

export function pluginNames(context) {
  const plugins = context.navigator?.plugins;
  if (!plugins) return [];

  return Array.from(plugins, (plugin) => plugin?.name).filter(Boolean).sort();
}

export async function canvasSignal(context) {
  const canvas = context.document?.createElement?.("canvas");
  const canvasContext = canvas?.getContext?.("2d");
  if (!canvasContext) return null;

  canvas.width = 240;
  canvas.height = 60;

  canvasContext.textBaseline = "alphabetic";
  canvasContext.fillStyle = "#f60";
  canvasContext.fillRect(0, 1, 62, 20);
  canvasContext.fillStyle = "#069";
  canvasContext.font = "11pt Arial";
  canvasContext.fillText("FLIT \u{1F512} device", 2, 15);
  canvasContext.fillStyle = "rgba(102, 204, 0, 0.7)";
  canvasContext.font = "18pt Arial";
  canvasContext.fillText("FLIT \u{1F512} device", 4, 45);

  return hash(canvas.toDataURL(), context);
}

export async function webglSignals(context) {
  const canvas = context.document?.createElement?.("canvas");
  const gl = canvas?.getContext?.("webgl") || canvas?.getContext?.("experimental-webgl");
  if (!gl) return { webgl: null, webgl_renderer: null };

  const debugInfo = gl.getExtension?.("WEBGL_debug_renderer_info");

  const renderer = debugInfo
    ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
    : gl.getParameter(gl.RENDERER);

  const vendor = debugInfo
    ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
    : gl.getParameter(gl.VENDOR);

  const parameters = {
    vendor,
    version: gl.getParameter(gl.VERSION),
    shading: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
    max_texture_size: gl.getParameter(gl.MAX_TEXTURE_SIZE),
    max_viewport: gl.getParameter(gl.MAX_VIEWPORT_DIMS)?.toString?.() ?? null,
    extensions: (gl.getSupportedExtensions?.() || []).slice().sort(),
  };

  return {
    webgl: await hash(parameters, context),
    // Kept in the clear: the server checks it for software renderers.
    webgl_renderer: renderer ?? null,
  };
}

export async function audioSignal(context) {
  const AudioContext = context.OfflineAudioContext || context.webkitOfflineAudioContext;
  if (!AudioContext) return null;

  const audioContext = new AudioContext(1, 5000, 44100);
  const oscillator = audioContext.createOscillator();
  const compressor = audioContext.createDynamicsCompressor();

  oscillator.type = "triangle";
  oscillator.frequency.value = 10000;

  compressor.threshold.value = -50;
  compressor.knee.value = 40;
  compressor.ratio.value = 12;
  compressor.attack.value = 0;
  compressor.release.value = 0.25;

  oscillator.connect(compressor);
  compressor.connect(audioContext.destination);
  oscillator.start(0);

  const buffer = await audioContext.startRendering();
  const samples = buffer.getChannelData(0).slice(2500, 3000);
  const total = Array.from(samples).reduce((sum, sample) => sum + Math.abs(sample), 0);

  return hash(total.toFixed(8), context);
}

export async function fontsSignal(context) {
  const document = context.document;
  const body = document?.body;
  const span = document?.createElement?.("span");
  if (!body || !span?.style) return null;

  span.style.position = "absolute";
  span.style.left = "-9999px";
  span.style.fontSize = FONT_TEST_SIZE;
  span.textContent = FONT_TEST_STRING;
  body.appendChild(span);

  const baseline = {};
  for (const font of BASELINE_FONTS) {
    span.style.fontFamily = font;
    baseline[font] = [span.offsetWidth, span.offsetHeight];
  }

  const available = [];
  for (const font of FONT_PROBES) {
    const detected = BASELINE_FONTS.some((base) => {
      span.style.fontFamily = `'${font}',${base}`;
      const [width, height] = baseline[base];
      return span.offsetWidth !== width || span.offsetHeight !== height;
    });

    if (detected) available.push(font);
  }

  body.removeChild(span);

  return hash(available, context);
}

/** Collect every signal. Returns the payload posted to /v1/collect. */
export async function collectSignals(context = globalThis) {
  const navigator = context.navigator || {};
  const agentData = await safely(() => userAgentData(context), { brands: null, platform: null });
  const webgl = await safely(() => webglSignals(context), { webgl: null, webgl_renderer: null });
  const { timezone, timezone_offset } = await safely(
    () => timezoneSignals(context),
    { timezone: null, timezone_offset: null },
  );

  return {
    user_agent: navigator.userAgent ?? null,
    ua_brands: agentData.brands,
    ua_platform: agentData.platform,
    platform: navigator.platform ?? null,
    languages: navigator.languages ? Array.from(navigator.languages) : null,
    timezone,
    timezone_offset,
    screen: await safely(() => screenSignals(context)),
    hardware_concurrency: navigator.hardwareConcurrency ?? null,
    device_memory: navigator.deviceMemory ?? null,
    touch_points: navigator.maxTouchPoints ?? null,
    plugins: await safely(() => pluginNames(context), []),
    webdriver: navigator.webdriver === true,
    canvas: await safely(() => canvasSignal(context)),
    webgl: webgl.webgl,
    webgl_renderer: webgl.webgl_renderer,
    audio: await safely(() => audioSignal(context)),
    fonts: await safely(() => fontsSignal(context)),
  };
}
