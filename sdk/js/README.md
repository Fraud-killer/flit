# @flit/browser

FLIT's browser SDK. It collects device signals in the page, exchanges them for a short-lived **visit token**, and lets your server attach that token to an audit.

No dependencies, no build step, about 8 KB of source.

## Install

```bash
npm install @flit/browser
```

Or load it straight from a page:

```html
<script type="module">
  import { collect } from "/node_modules/@flit/browser/src/index.js";
</script>
```

## Use

```js
import { collect } from "@flit/browser";

const { visitToken } = await collect({
  key: "flit_pk_...",                       // your application's collection key
  endpoint: "https://api.flit.io/api/v1/collect",
});

// Send visitToken to your own backend with the rest of the checkout payload.
await fetch("/checkout", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ ...order, visit_token: visitToken }),
});
```

Your server then includes it when asking FLIT to audit the event:

```json
{ "id": "tx_123", "type": "debit", "amount": 25, "currency_code": "NGN",
  "client_id": "user_1", "visit_token": "..." }
```

Tokens last 30 minutes and are meant to be used once, for the action the user just took.

### Options

| Option | Default | Meaning |
|---|---|---|
| `key` | required | Your application's collection key (`flit_pk_...`) |
| `endpoint` | `https://api.flit.io/api/v1/collect` | Where to post |
| `timeoutMs` | `5000` | Give up rather than delay your checkout |
| `context` | `globalThis` | The browser globals to read; injected in tests |
| `signals` | collected | Pass your own to skip collection |

`collect` throws `FlitError` on a bad key, a failed request or a timeout. **Wrap it and carry on**: fraud checking should never block a purchase. Without a token FLIT still scores the event, just with less to go on.

## What it collects

Rendering and hardware traits that distinguish one device from another: canvas, WebGL (including the unmasked renderer), audio, available fonts, screen, timezone, languages, platform, CPU cores, memory, touch points, plugins and the WebDriver flag.

**Identifying material never leaves the browser.** Canvas images, audio buffers and font lists are hashed with SHA-256 in the page; only digests are sent. The one exception is the WebGL renderer string, which the server reads to spot software rendering (VMs and headless browsers). The server hashes everything again before storing, so no raw signal is ever written to the database.

## The device key

The first response includes a `device_key`, which the SDK stores in `localStorage` and returns on later visits. It helps FLIT recognise a device whose fingerprint has drifted, for example after a browser update.

It is a hint, not a credential: a copied key cannot make one device pass as another, because the signals still have to broadly agree. If storage is blocked or cleared, everything still works; identification just leans entirely on the signals.

## Restricting your key

The key is public, so lock it to your sites with the application's `collect_origins` allowlist (exact origins, or `https://*.example.com` for subdomains). An unlisted site gets a 403 it cannot read. An empty list accepts any origin.

## Privacy

- Collection is explicit: nothing runs until you call `collect`.
- No cookies are set or read, and requests are sent with `credentials: "omit"`.
- Only hashes are stored, so the database holds no browsing-identifying raw values.
- Devices are not linked across merchants. Each application gets its own view.

Tell your users what you collect and why, in whatever notice your jurisdiction requires.

## Tests

```bash
npm test
```

The tests run against a fake browser context, so no real browser is needed.
