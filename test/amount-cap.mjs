/**
 * Amount-cap bypass via the query string.
 *
 * Reproduced against the compiled build: a rule `{action:'allow',
 * amountLimit:{field:'amount',max:5000}}` on POST /v1/charges denied a body of
 * `amount=1&amount=999999` (duplicate keys are ambiguous, so the reader refuses
 * to guess) -- but the SAME body at `/v1/charges?amount=1` was ALLOWED, because
 * evaluate() treated the refusal as "no amount found" and let the query supply
 * one. The shipped policy.example.json rule `stripe-charge-cap` is this shape.
 */
import assert from 'assert/strict';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const D = (rel) => require(path.join(here, '..', 'dist', rel));
const { PolicyEngine } = D('policy/policy.js');

// A label is printed only once the assertions that FOLLOW it have run without
// throwing. Printing on call would show `PASS x` immediately above the failure
// of x, which is the same "reports success it has not confirmed" pattern this
// suite exists to catch elsewhere.
let passed = 0;
let pending = null;
function flush() {
  if (pending !== null) { passed++; console.log(`  PASS  ${pending}`); pending = null; }
}
const check = (n) => { flush(); pending = n; };
process.on('exit', flush);

const engineFor = (field) => new PolicyEngine({
  defaultAction: 'deny',
  egressAllowlist: ['api.stripe.com'],
  rules: [{ id: 'cap', action: 'allow', match: { hosts: ['api.stripe.com'], paths: ['/v1/charges'] }, amountLimit: { field, max: 5000 } }],
});
const engine = engineFor('amount');
const body = (s) => Buffer.from(s, 'utf8');
const ev = (p, b, ct) => engine.evaluate({ host: 'api.stripe.com', method: 'POST', path: p, body: b, contentType: ct });

check('under the cap is allowed (control)');
assert.equal(ev('/v1/charges', body('amount=100&currency=usd'), 'application/x-www-form-urlencoded').action, 'allow');

check('over the cap is denied (control)');
assert.equal(ev('/v1/charges', body('amount=999999'), 'application/x-www-form-urlencoded').action, 'deny');

check('duplicate keys in the body are refused, with no query present');
assert.equal(ev('/v1/charges', body('amount=1&amount=999999'), 'application/x-www-form-urlencoded').action, 'deny');

check('THE BYPASS: a query amount cannot overrule a refused body');
const bypass = ev('/v1/charges?amount=1', body('amount=1&amount=999999'), 'application/x-www-form-urlencoded');
assert.equal(bypass.action, 'deny', 'query amount overrode the body refusal - cap bypassed');

check('a non-numeric body amount cannot be rescued by the query either');
assert.equal(ev('/v1/charges?amount=1', body('amount=notanumber'), 'application/x-www-form-urlencoded').action, 'deny');
assert.equal(ev('/v1/charges?amount=1', body('{"amount":"abc"}'), 'application/json').action, 'deny');

check('body and query disagreeing is refused rather than guessed');
assert.equal(ev('/v1/charges?amount=1', body('amount=999999'), 'application/x-www-form-urlencoded').action, 'deny');
assert.equal(ev('/v1/charges?amount=999999', body('amount=1'), 'application/x-www-form-urlencoded').action, 'deny');

check('body and query agreeing is still allowed');
assert.equal(ev('/v1/charges?amount=100', body('amount=100'), 'application/x-www-form-urlencoded').action, 'allow');

check('the query alone still enforces the cap when the body has none');
assert.equal(ev('/v1/charges?amount=100', null).action, 'allow');
assert.equal(ev('/v1/charges?amount=999999', null).action, 'deny');

check('a dotted cap is not satisfied by a bare top-level query param');
const nested = engineFor('transfer_data.amount');
const nev = (p, b, ct) => nested.evaluate({ host: 'api.stripe.com', method: 'POST', path: p, body: b, contentType: ct });
// `?amount=1` is a DIFFERENT field; it must not satisfy a cap on transfer_data.amount.
assert.equal(nev('/v1/charges?amount=1', body('{"transfer_data":{"amount":999999}}'), 'application/json').action, 'deny');
assert.equal(nev('/v1/charges?amount=1', null).action, 'deny');

check('a dotted cap IS read from its real spellings');
assert.equal(nev('/v1/charges', body('{"transfer_data":{"amount":100}}'), 'application/json').action, 'allow');
assert.equal(nev('/v1/charges', body('{"transfer_data":{"amount":999999}}'), 'application/json').action, 'deny');
assert.equal(nev('/v1/charges?transfer_data%5Bamount%5D=100', null).action, 'allow');
assert.equal(nev('/v1/charges?transfer_data%5Bamount%5D=999999', null).action, 'deny');

check('a mutating request with no readable amount anywhere fails closed');
assert.equal(ev('/v1/charges', null).action, 'deny');
assert.equal(ev('/v1/charges', body('currency=usd'), 'application/x-www-form-urlencoded').action, 'deny');

flush();
console.log(`\nAmount cap: ${passed} assertions passed`);
