/**
 * Environment sanitization for launched/child processes.
 *
 * A launched agent (or any `airlock run -- <cmd>` child) is UNTRUSTED. The point
 * of the airlock is that the agent is handed placeholders instead of real keys —
 * but that only holds for the secrets the airlock itself injects. Everything
 * else the operator happens to have exported is inherited by the child unless it
 * is removed here, and an agent that receives `SUPABASE_SERVICE_ROLE_KEY` from
 * the ambient environment is exactly as compromised as one handed the vault.
 *
 * So this strips three classes:
 *
 * 1. The airlock's own namespace, whole. The daemon's environment may carry the
 *    vault-sealing passphrase (AIRLOCK_PASSPHRASE / AIRLOCK_PASSPHRASE_FILE),
 *    which together with vdk.seal + vault.enc on disk decrypts the entire vault
 *    offline. The sweep is by NAMESPACE rather than a fixed list so a future
 *    AIRLOCK_* variable cannot be forgotten. `wiredEnv()` re-adds the ones the
 *    child is meant to see (AIRLOCK_ACTIVE, proxy and CA vars) on top.
 *
 * 2. Third-party credentials, by name and by value shape. Name matching is a
 *    denylist and a denylist cannot be completed — a key stored as `STRIPE_SK`
 *    or `MY_CORP_XYZ` matches no word list — so the value is checked too:
 *    whatever an operator called it, something shaped like a live provider key
 *    is treated as one.
 *
 * 3. Variables that make a child execute code it was not asked to run
 *    (NODE_OPTIONS, LD_PRELOAD, BASH_ENV and friends). Those are not secrets;
 *    they are a way to turn "spawn this command" into "spawn this command plus
 *    whatever I like", which matters when the thing being spawned is untrusted.
 *
 * A profile's explicit `env` is layered on AFTER this and is never filtered:
 * naming a variable in a profile is an operator decision, and this function has
 * no business overriding it.
 */

/** Matches every variable in the airlock's own configuration namespace. */
const AIRLOCK_NS_RE = /^AIRLOCK_/i;

/**
 * Word-anchored credential names. Anchored between `_` or a string edge, which
 * is correct for `API_KEY` and `ACCESS_KEY` and keeps `MONKEY_PATCH` intact.
 */
const INHERITED_SECRET_NAME =
  /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSPHRASE|CREDENTIALS?|PRIVATE_?KEY|ACCESS_?KEY|AUTH)(?:$|_)/i;

/** Names that are credentials outright, matched exactly. */
const INHERITED_SECRET_EXACT = new Set([
  'AIRLOCK_PASSPHRASE',
  'DATABASE_URL',
  'REDIS_URL',
  'MONGODB_URI',
  'SENTRY_DSN',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'PGPASSWORD',
  'PGPASSFILE',
  'MYSQL_PWD',
  'GITHUB_PAT',
  'GITLAB_TOKEN',
  'DOCKER_AUTH_CONFIG',
  'KUBECONFIG',
]);

/**
 * Words essentially never innocent in a variable name, matched as SUBSTRINGS
 * rather than at `_` boundaries.
 *
 * [INHERITED_SECRET_NAME] anchors each word, which leaves real gaps for
 * run-together names. Verified to pass straight through to a child:
 *
 *   NPM_CONFIG_//registry.npmjs.org/:_authToken
 *       uppercases to ..._AUTHTOKEN. `TOKEN` is preceded by `H`, not `_`, and
 *       `AUTH` is followed by `T`, not `_`, so neither alternative fires.
 *
 * Only words with no plausible innocent use are listed. `KEY`, `AUTH` and `API`
 * deliberately stay boundary-anchored above, because as substrings they would
 * strip `MONKEY_*`, `KEYBOARD_*` and `AUTHORITY_*`.
 */
const INHERITED_SECRET_SUBSTRING = /(?:TOKEN|SECRET|PASSWORD|PASSPHRASE|CREDENTIAL|WEBHOOK)/i;

/**
 * A bare `KEY` word, which [INHERITED_SECRET_NAME] does not cover at all — it
 * only matches `KEY` when preceded by API, ACCESS or PRIVATE. Measured against
 * a built launcher, these ALL reached the child: SUPABASE_SERVICE_ROLE_KEY (the
 * canonical Supabase name, and a full row-level-security bypass), SUPABASE_KEY,
 * ENCRYPTION_KEY, MASTER_KEY, SIGNING_KEY, JWT_SIGNING_KEY, DEPLOY_KEY, SSH_KEY,
 * AZURE_OPENAI_KEY. Value-shape detection does not save them: they hold opaque
 * random bytes, not a recognisable provider format. Only the name can catch them.
 *
 * THE TRADE-OFF, STATED RATHER THAN HIDDEN. `KEY` is not always a credential:
 * `PARTITION_KEY`, `SORT_KEY`, `PRIMARY_KEY` and `ROW_KEY` are database field
 * names and will be stripped from a launched agent's ambient environment too.
 * That is the deliberate choice for a credential firewall — a `*_KEY` variable
 * in the daemon's environment is far more likely to be a live secret than a
 * schema hint, and the cost of being wrong the other way is a leaked
 * service-role key. An agent that genuinely needs a field name receives it
 * through its profile `env`, which is explicit and never filtered.
 *
 * Word-boundary anchored, so `KEYBOARD_LAYOUT` and `MONKEY_PATCH` are untouched.
 */
const INHERITED_KEY_WORD = /(?:^|_)KEYS?(?:$|_)/i;

/**
 * The one known-innocent name containing a listed substring.
 *
 * `TOKENIZERS_PARALLELISM` is a HuggingFace setting that suppresses a fork
 * warning; it carries nothing sensitive, and stripping it would change the
 * behaviour of a working agent for no security gain. A single named carve-out
 * is honest; a general "unless it looks configury" escape hatch would not be.
 */
const INNOCENT_SUBSTRING_NAMES = /^TOKENIZERS?(?:_|$)/i;

/**
 * Provider credential formats, matched against the VALUE. Every pattern is
 * anchored and length-qualified so a coincidental match is implausible. These
 * are additive to the name rules, never a replacement.
 */
const CREDENTIAL_SHAPED_VALUE: RegExp[] = [
  /^sk-[A-Za-z0-9_-]{20,}$/,                        // OpenAI and compatible
  /^sk-ant-[A-Za-z0-9_-]{20,}$/,                    // Anthropic
  /^(?:pk|sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}$/,  // Stripe
  /^gh[pousr]_[A-Za-z0-9]{36,}$/,                   // GitHub PAT / OAuth / refresh
  /^github_pat_[A-Za-z0-9_]{50,}$/,                 // GitHub fine-grained PAT
  /^glpat-[A-Za-z0-9_-]{20,}$/,                     // GitLab PAT
  /^xox[baprs]-[A-Za-z0-9-]{10,}$/,                 // Slack
  /^AIza[0-9A-Za-z_-]{35}$/,                        // Google API key
  /^AKIA[0-9A-Z]{16}$/,                             // AWS access key id
  /^ASIA[0-9A-Z]{16}$/,                             // AWS temporary access key id
  /^hf_[A-Za-z0-9]{30,}$/,                          // HuggingFace
  /^dop_v1_[a-f0-9]{64}$/,                          // DigitalOcean
  /^SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/,   // SendGrid
  /^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./, // JWT with a JSON header+payload
];

/**
 * Checked separately from [CREDENTIAL_SHAPED_VALUE] because a PEM key is the one
 * credential that legitimately runs to many kilobytes, so it must be tested
 * before the length bound rather than after it.
 */
const PEM_PRIVATE_KEY = /^-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}/;

/**
 * Variables that turn "spawn this command" into "spawn this command plus
 * whatever I like". Not secrets — an execution channel into an untrusted child.
 */
const CHILD_CODE_INJECTION_ENV = new Set([
  'NODE_OPTIONS',
  'NODE_PATH',
  'LD_PRELOAD',
  'DYLD_INSERT_LIBRARIES',
  'BASH_ENV',
  'ENV',
  'RUBYOPT',
  'PERL5OPT',
]);

/** A `*_URL`/`*_URI` carrying userinfo, or a database DSN, is a credential. */
function credentialBearingUrl(name: string, value: string): boolean {
  if (!/(?:URL|URI)$/i.test(name)) return false;
  try {
    const parsed = new URL(value);
    return !!parsed.username || !!parsed.password ||
      /^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):$/i.test(parsed.protocol);
  } catch {
    return /:\/\/[^\s/@:]+:[^\s/@]+@/.test(value);
  }
}

function credentialShapedValue(value: string): boolean {
  if (value.length < 16) return false;
  if (PEM_PRIVATE_KEY.test(value)) return true;
  // Bound the remaining work: every pattern above is a short opaque token, so a
  // value larger than this can only be a blob or a document, and running a
  // dozen regexes across it on every child spawn would be wasted effort.
  if (value.length > 4096) return false;
  return CREDENTIAL_SHAPED_VALUE.some((re) => re.test(value));
}

/** True when this name/value pair must not reach an untrusted child. */
export function sensitiveEnvName(name: string, value: string): boolean {
  const upper = name.toUpperCase();
  return INHERITED_SECRET_EXACT.has(upper) ||
    INHERITED_SECRET_NAME.test(upper) ||
    (INHERITED_SECRET_SUBSTRING.test(upper) && !INNOCENT_SUBSTRING_NAMES.test(upper)) ||
    INHERITED_KEY_WORD.test(upper) ||
    /(?:^|_)(?:PAT|COOKIE|SESSION|DSN)(?:$|_)/i.test(upper) ||
    credentialBearingUrl(upper, value) ||
    credentialShapedValue(value);
}

/**
 * A copy of `src` (default process.env) with the AIRLOCK_* namespace, inherited
 * third-party credentials, and child code-injection variables removed.
 */
export function sanitizedEnv(src: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...src };
  for (const k of Object.keys(out)) {
    if (AIRLOCK_NS_RE.test(k)) { delete out[k]; continue; }
    if (CHILD_CODE_INJECTION_ENV.has(k.toUpperCase())) { delete out[k]; continue; }
    const v = out[k];
    if (typeof v === 'string' && sensitiveEnvName(k, v)) delete out[k];
  }
  return out;
}
