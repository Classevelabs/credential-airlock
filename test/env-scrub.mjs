/**
 * A launched agent must not inherit the operator's credentials.
 *
 * Until this suite existed, sanitizedEnv() removed exactly one thing: the
 * AIRLOCK_* namespace. That protected the vault passphrase and nothing else, so
 * every third-party credential the operator happened to have exported was
 * handed to the untrusted child — SUPABASE_SERVICE_ROLE_KEY (a full
 * row-level-security bypass), OPENAI_API_KEY, GITHUB_TOKEN, AWS keys, database
 * URLs with inline passwords. The product's whole claim is that the agent is
 * handed placeholders rather than real keys; that claim was true only of the
 * secrets the airlock itself injected.
 *
 * The cases below are grouped by the mechanism that catches them, because each
 * mechanism exists for a reason and a regression in one is invisible if another
 * happens to cover the same fixture.
 */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const { sanitizedEnv } = require(path.join(here, '..', 'dist', 'util', 'env.js'));

let pass = 0;
let fail = 0;
function ok(label, cond, extra) {
  if (cond) { pass++; console.log(`  PASS  ${label}`); }
  else { fail++; console.log(`  FAIL  ${label}${extra ? '  ' + extra : ''}`); }
}
function stripped(name, value) {
  const out = sanitizedEnv({ [name]: value, HOME: '/h' });
  return !(name in out);
}

console.log('\nenv-scrub: the ambient environment a launched agent inherits');

// --- the airlock's own namespace (the original behaviour, still required) ---
for (const n of ['AIRLOCK_PASSPHRASE', 'AIRLOCK_PASSPHRASE_FILE', 'AIRLOCK_SEALER', 'AIRLOCK_HOME']) {
  ok(`airlock namespace: ${n} stripped`, stripped(n, 'x'));
}

// --- bare _KEY: the gap the value-shape rule cannot cover -------------------
// These hold opaque random bytes, not a recognisable provider format, so only
// the NAME can catch them. INHERITED_SECRET_NAME matches KEY only when preceded
// by API, ACCESS or PRIVATE, so every one of these reached the child.
for (const n of [
  'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_KEY', 'ENCRYPTION_KEY', 'MASTER_KEY',
  'SIGNING_KEY', 'JWT_SIGNING_KEY', 'DEPLOY_KEY', 'SSH_KEY', 'AZURE_OPENAI_KEY',
]) {
  ok(`bare _KEY: ${n} stripped`, stripped(n, 'opaque-random-bytes-not-a-known-format'));
}

// --- word-anchored credential names ----------------------------------------
for (const n of ['OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'DB_PASSWORD', 'MY_PRIVATE_KEY']) {
  ok(`name rule: ${n} stripped`, stripped(n, 'value'));
}

// --- run-together names the boundary anchor misses -------------------------
ok('substring rule: NPM_CONFIG__AUTHTOKEN stripped', stripped('NPM_CONFIG__AUTHTOKEN', 'v'));
ok('substring rule: MY_APITOKEN stripped', stripped('MY_APITOKEN', 'v'));

// --- exact names ------------------------------------------------------------
for (const n of ['DATABASE_URL', 'PGPASSWORD', 'KUBECONFIG', 'DOCKER_AUTH_CONFIG']) {
  ok(`exact name: ${n} stripped`, stripped(n, 'v'));
}

// --- value shape: a denylist cannot be completed, so the value is read too ---
const shaped = {
  STRIPE_SK: 'sk_live_' + 'a'.repeat(24),
  MY_CORP_XYZ: 'sk-ant-' + 'b'.repeat(24),
  RANDOM_NAME: 'ghp_' + 'c'.repeat(36),
  NOTHING_OBVIOUS: 'AKIA' + 'D'.repeat(16),
};
for (const [n, v] of Object.entries(shaped)) {
  ok(`value shape: ${n} stripped on its value alone`, stripped(n, v));
}
ok('value shape: PEM private key stripped regardless of length',
  stripped('SOME_BLOB', '-----BEGIN RSA PRIVATE KEY-----\n' + 'x'.repeat(5000)));

// --- credential-bearing URLs -----------------------------------------------
ok('url: inline userinfo stripped', stripped('SERVICE_URL', 'https://user:pw@example.com/'));
ok('url: postgres DSN stripped', stripped('STORE_URI', 'postgresql://h/db'));

// --- code-injection channels into an untrusted child ------------------------
for (const n of ['NODE_OPTIONS', 'LD_PRELOAD', 'BASH_ENV', 'PERL5OPT', 'DYLD_INSERT_LIBRARIES']) {
  ok(`code injection: ${n} stripped`, stripped(n, '--require=/tmp/x'));
}

// --- false positives: an over-eager filter breaks working agents ------------
for (const [n, v] of Object.entries({
  KEYBOARD_LAYOUT: 'us',
  MONKEY_PATCH: '1',
  AUTHORITY_URL: 'https://example.com/',
  RAPIDLY: 'yes',
  TOKENIZERS_PARALLELISM: 'false',
  PATH: '/usr/bin',
  HOME: '/home/x',
  LANG: 'en_US.UTF-8',
})) {
  ok(`kept: ${n}`, !stripped(n, v), `(value ${JSON.stringify(v)})`);
}

// --- the sweep must not mutate the caller's object --------------------------
{
  const src = { OPENAI_API_KEY: 'x', PATH: '/usr/bin' };
  sanitizedEnv(src);
  ok('source env object is not mutated', src.OPENAI_API_KEY === 'x');
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
