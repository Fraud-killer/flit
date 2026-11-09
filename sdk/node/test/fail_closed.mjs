/**
 * No answer on money out means no transfer.
 *
 *     node sdk/node/test/fail_closed.mjs
 */
import assert from "node:assert/strict";
import { failClosed, failOpen } from "../flit.mjs";

const reject = Promise.reject(new Error("timed out"));
assert.equal((await failClosed(reject)).should_block, true);

// What a 429 looks like to the client: JSON, with no decision in it.
const refused = await failClosed(Promise.resolve({ errors: [{ code: "rate_limited" }] }));
assert.equal(refused.should_block, true);
assert.equal(refused.unavailable, true);

const decided = await failClosed(Promise.resolve({ data: { should_block: false } }));
assert.deepEqual(decided, { should_block: false });

// The signup path keeps its opposite trade.
assert.equal((await failOpen(Promise.reject(new Error("down")))).should_block, false);

console.log("ok");
