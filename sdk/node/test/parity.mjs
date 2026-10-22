/**
 * Checks this client's signing against the Python implementation that
 * verifies it.
 *
 * Run from the repository root:
 *
 *     node sdk/node/test/parity.mjs
 *
 * It prints each case's signature and exits non-zero on any mismatch. The
 * Python side is invoked directly rather than reimplemented, so this cannot
 * pass by both sides sharing the same mistake.
 */

import { execFileSync } from "node:child_process";
import { signature } from "../flit.mjs";

const PYTHON = process.env.FLIT_PYTHON || "python3";

const CASES = {
  "plain ascii": { id: "signup_1", email: "ada@gmail.com", country: "NG" },

  // Python escapes non-ASCII, JavaScript does not. This is the case that
  // breaks a naive client, and it breaks it intermittently.
  "non-ascii": { id: "s2", email: "José.Ökafor@gmail.com", name: "Zoë" },

  "nested and mixed types": {
    id: "s3",
    amount: 1234.5,
    ok: true,
    missing: null,
    nested: { b: 2, a: [1, "x", null, true] },
  },

  // Key order must not matter: both sides sort.
  "unsorted keys": { zebra: 1, apple: 2, Mango: 3, "1first": 4 },

  "empty body": {},
};

const PY = `
import json, sys, signit
from devkit import create_hash_value
body = json.loads(sys.argv[1])
message = create_hash_value(dict(
    path=sys.argv[2], method="post", body_hash=create_hash_value(body),
    timestamp=sys.argv[3], content_type="application/json",
))
print(signit.signature.create(sys.argv[4], sys.argv[5], message))
`;

const PATH = "/api/v1/applications/app-id/audit-registration";
const TIMESTAMP = "1700000000000";
const APPLICATION = "app-id";
const SECRET = "s3cret-key";

let failures = 0;

for (const [name, body] of Object.entries(CASES)) {
  const mine = signature({
    applicationId: APPLICATION,
    secretKey: SECRET,
    method: "POST",
    path: PATH,
    body,
    timestamp: TIMESTAMP,
  });

  const theirs = execFileSync(
    PYTHON,
    ["-c", PY, JSON.stringify(body), PATH, TIMESTAMP, APPLICATION, SECRET],
    { cwd: "app", encoding: "utf8" },
  ).trim();

  const ok = mine === theirs;
  if (!ok) failures += 1;

  console.log(`${ok ? "ok  " : "FAIL"}  ${name}`);
  if (!ok) {
    console.log(`        node   ${mine}`);
    console.log(`        python ${theirs}`);
  }
}

console.log(
  failures === 0
    ? `\nAll ${Object.keys(CASES).length} cases match the Python verifier.`
    : `\n${failures} mismatch(es).`,
);

process.exit(failures === 0 ? 0 : 1);
