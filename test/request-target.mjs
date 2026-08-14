/**
 * Request-target normalisation — the policy-bypass class.
 *
 * Each spelling below was verified against the compiled build to evade a
 * path-scoped deny rule and fall through to the host-wide `allow-secret-<name>`
 * rule the product auto-creates on every `secret set`, with the real credential
 * injected. They are regression tests for a live bypass, not hypotheticals.
 *
 * The second half is the safety half: normalisation must not rewrite a request
 * into a different resource, or the fix would break working integrations.
 */
import assert from 'assert/strict';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const D = (rel) => require(path.join(here, '..', 'dist', rel));
const { normalizeRequestTarget, InvalidRequestTarget } = D('util/request-target.js');

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
const norm = (t) => normalizeRequestTarget(t).target;

// ── the bypasses ───────────────────────────────────────────────────────

check('absolute-form is refused, not rewritten', () => {});
assert.throws(
  () => normalizeRequestTarget('https://api.stripe.com/v1/refunds'),
  InvalidRequestTarget,
  'absolute-form must be refused inside a tunnel'
);
assert.throws(() => normalizeRequestTarget('http://evil.example/v1/refunds'), InvalidRequestTarget);
assert.throws(() => normalizeRequestTarget('api.stripe.com:443'), InvalidRequestTarget);

check('dot-segments resolve to the resource the origin will serve');
assert.equal(norm('/v1/./refunds'), '/v1/refunds');
assert.equal(norm('/v1/x/../refunds'), '/v1/refunds');
assert.equal(norm('/v1/a/b/../../refunds'), '/v1/refunds');
// A `..` at the root must not climb out.
assert.equal(norm('/../../v1/refunds'), '/v1/refunds');

check('duplicate slashes collapse');
assert.equal(norm('//v1/refunds'), '/v1/refunds');
assert.equal(norm('/v1//refunds'), '/v1/refunds');
assert.equal(norm('/v1///refunds'), '/v1/refunds');

check('percent-encoded unreserved characters decode');
assert.equal(norm('/v1/%72efunds'), '/v1/refunds');
assert.equal(norm('/v1/%63harges'), '/v1/charges');
assert.equal(norm('/v1/refund%73'), '/v1/refunds');

check('the combined spelling collapses too');
assert.equal(norm('//v1/./x/../%72efunds'), '/v1/refunds');

// ── the safety half ────────────────────────────────────────────────────

check('reserved characters stay encoded, so %2F cannot become a separator');
// If %2F decoded, `/v1/a%2Fb` would gain a path segment it never had and could
// match a rule written for a different resource.
assert.equal(norm('/v1/a%2Fb'), '/v1/a%2Fb');
assert.equal(norm('/v1/a%3Fb'), '/v1/a%3Fb');
assert.equal(norm('/v1/a%23b'), '/v1/a%23b');

check('escapes that remain are uppercased for stable matching');
assert.equal(norm('/v1/a%2fb'), '/v1/a%2Fb');

check('a trailing slash is preserved — it is a different resource');
assert.equal(norm('/v1/refunds/'), '/v1/refunds/');
assert.equal(norm('/'), '/');

check('the query string is passed through untouched');
assert.equal(norm('/v1/charges?amount=1&currency=usd'), '/v1/charges?amount=1&currency=usd');
assert.equal(norm('/v1/./charges?a=%2F'), '/v1/charges?a=%2F');
// Normalisation must not reach into the query: `?a=b//c` is data, not a path.
assert.equal(norm('/v1/x?a=b//c'), '/v1/x?a=b//c');
assert.equal(norm('/v1/x?a=%2e%2e'), '/v1/x?a=%2e%2e');

check('ordinary paths are returned unchanged');
for (const p of [
  '/v1/charges', '/', '/a/b/c', '/v1/charges?x=1',
  '/api/v2/items/42', '/health', '/.well-known/openid-configuration',
]) {
  assert.equal(norm(p), p, `${p} was rewritten`);
}

check('an empty or missing target becomes /');
assert.equal(norm(undefined), '/');
assert.equal(norm(''), '/');

check('asterisk-form survives for OPTIONS');
assert.equal(norm('*'), '*');

check('control characters are refused');
assert.throws(() => normalizeRequestTarget('/v1/x\r\nX-Injected: 1'), InvalidRequestTarget);
assert.throws(() => normalizeRequestTarget('/v1/x\0'), InvalidRequestTarget);

check('a protocol-relative target that looks like an authority is refused');
assert.throws(() => normalizeRequestTarget('//evil.example/v1/refunds'), InvalidRequestTarget);
assert.throws(() => normalizeRequestTarget('//user@evil/v1'), InvalidRequestTarget);

check('a stray percent is left alone rather than guessed at');
assert.equal(norm('/v1/100%'), '/v1/100%');
assert.equal(norm('/v1/%zz'), '/v1/%zz');

// -- the security property, against the real policy engine --------------
//
// String normalisation is not the claim. The claim is that a path-scoped deny
// can no longer be evaded into the host-wide allow that maintainPolicyForSecret
// auto-creates on every `secret set`. This builds exactly that policy shape --
// the one docs/ADAPTERS.md tells operators to use -- and drives the compiled
// PolicyEngine with each bypass spelling as the proxy now delivers it.
const { PolicyEngine } = D('policy/policy.js');

const engine = new PolicyEngine({
  defaultAction: 'deny',
  egressAllowlist: ['api.stripe.com'],
  rules: [
    { id: 'deny-refunds', action: 'deny', match: { hosts: ['api.stripe.com'], methods: ['POST'], paths: ['/v1/refunds'] } },
    { id: 'allow-secret-stripe', action: 'allow', match: { hosts: ['api.stripe.com'] } },
  ],
});

const BYPASSES = [
  '/v1/refunds/', '//v1/refunds', '/v1/%72efunds', '/v1/./refunds',
  '/v1/x/../refunds', '/v1//refunds', '/v1/./x/../%72efunds',
];

check('the canonical spelling is denied (control)');
assert.equal(engine.evaluate({ host: 'api.stripe.com', method: 'POST', path: '/v1/refunds', body: null }).action, 'deny');

check('every bypass spelling is denied once normalised');
for (const raw of BYPASSES) {
  let normalised;
  try { normalised = norm(raw); } catch (e) { continue; }
  const decision = engine.evaluate({ host: 'api.stripe.com', method: 'POST', path: normalised, body: null });
  assert.equal(decision.action, 'deny',
    raw + ' -> ' + normalised + ' was ALLOWED by ' + decision.ruleId + ' - the refund gate is still evadable');
}

check('a genuinely different resource is still allowed');
assert.equal(engine.evaluate({ host: 'api.stripe.com', method: 'POST', path: norm('/v1/charges'), body: null }).action, 'allow');
assert.equal(engine.evaluate({ host: 'api.stripe.com', method: 'GET', path: norm('/v1/refunds'), body: null }).action, 'allow');

flush();
console.log(`\nRequest-target normalisation: ${passed} assertions passed`);
