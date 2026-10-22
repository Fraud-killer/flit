/**
 * End-to-end smoke test against a running FLIT.
 *
 * The parity test checks that this client signs the way the server verifies.
 * It cannot check that the client is *usable*: it pins a fixed timestamp, so
 * both sides agreed on a value that the replay-protection middleware would
 * have rejected, and it sends no headers at all. Two real defects hid behind
 * a green parity run — a timestamp in milliseconds where seconds were
 * expected, and a missing nonce header. Only an actual request found them.
 *
 * Usage:
 *
 *     python manage.py provision_application "Smoke" --owner you@example.com
 *     FLIT_URL=http://127.0.0.1:8000 \
 *     FLIT_APPLICATION_ID=... FLIT_SECRET_KEY=... \
 *       node sdk/node/test/smoke.mjs
 */

import { Flit, failOpen } from "../flit.mjs";

const { FLIT_URL, FLIT_APPLICATION_ID, FLIT_SECRET_KEY } = process.env;

if (!FLIT_URL || !FLIT_APPLICATION_ID || !FLIT_SECRET_KEY) {
  console.error(
    "Set FLIT_URL, FLIT_APPLICATION_ID and FLIT_SECRET_KEY. Provision an " +
    "application with: python manage.py provision_application ...",
  );
  process.exit(2);
}

const flit = new Flit({
  baseUrl: FLIT_URL,
  applicationId: FLIT_APPLICATION_ID,
  secretKey: FLIT_SECRET_KEY,
});

// The September 2026 signup flood: bulk registrations from one IP, a bare
// HTTP client, and addresses named after the unix clock.
const attacker = await failOpen(
  flit.auditRegistration({
    id: "smoke_attacker",
    client_id: "smoke_attacker",
    email: "figomass1789844685@uberip.com",
    country: "NG",
    ip_address: "193.200.229.243",
    user_agent: "curl/8.20.0",
    action: "registration",
  }),
  (error) => console.error("  request failed:", error.message),
);

const customer = await failOpen(
  flit.auditRegistration({
    id: "smoke_customer",
    client_id: "smoke_customer",
    email: "real.person@gmail.com",
    country: "KE",
    ip_address: "105.160.1.20",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    action: "registration",
  }),
);

function show(label, decision) {
  console.log(
    `  ${label.padEnd(20)} score=${(decision.risk_score ?? 0).toFixed(3)}` +
    `  would_block=${decision.would_block}` +
    `  should_block=${decision.should_block}` +
    `  mode=${decision.enforcement}`,
  );
  if (decision.factors?.length) {
    console.log(" ".repeat(24) + decision.factors.join(", "));
  }
}

console.log("");
show("bulk signup", attacker);
show("real customer", customer);
console.log("");

const problems = [];

if (attacker.unavailable || customer.unavailable) {
  problems.push("FLIT did not answer — check credentials, URL and clock");
}
if (!attacker.would_block && !attacker.would_challenge) {
  problems.push("the bulk signup was not acted on");
}
if (customer.would_block || customer.would_challenge) {
  problems.push("the real customer would have been stopped");
}
if (attacker.enforcement === "shadow" && attacker.should_block) {
  problems.push("shadow mode did not suppress the block");
}

for (const problem of problems) console.error("  FAIL  " + problem);

console.log(
  problems.length === 0
    ? `Smoke test passed (${attacker.enforcement} mode).`
    : `${problems.length} problem(s).`,
);

process.exit(problems.length === 0 ? 0 : 1);
