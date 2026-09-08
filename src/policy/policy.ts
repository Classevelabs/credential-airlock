/**
 * Policy engine. Deny-by-default at two layers:
 *   1. Egress: the host must match the egress allowlist, or the request is denied.
 *   2. Rules: within an allowed host, the FIRST matching rule's action wins
 *      (allow | deny | require_approval). No matching rule => defaultAction (deny).
 * Rules may carry a rate limit (sliding window) and an amount cap (a hard ceiling
 * on a named numeric body field, e.g. Stripe `amount`).
 */
import { Policy, PolicyAction, PolicyDecision, PolicyRule, RateLimit } from '../types';
import { matchAnyHost, matchAnyPath } from '../util/glob';

export interface EvalCtx {
  host: string;
  method: string;
  path: string;
  body: Buffer | null;
  contentType?: string;
}

/**
 * Extract a numeric amount from a request body. Robust against attacker-chosen
 * content-types and leading whitespace/BOM: it does NOT trust the content-type
 * to decide whether to parse — it attempts JSON whenever the body looks like
 * JSON after trimming, and always tries a urlencoded fallback.
 */
export function extractAmount(body: Buffer | null, contentType: string | undefined, field: string): number | undefined {
  if (!body || !body.length) return undefined;
  const text = body.toString('utf8');
  const trimmed = text.replace(/^[﻿\s]+/, '');
  const ct = (contentType || '').toLowerCase();
  if (ct.includes('application/json') || trimmed[0] === '{' || trimmed[0] === '[') {
    try {
      const obj = JSON.parse(trimmed) as unknown;
      const val = field
        .split('.')
        .reduce<unknown>((acc, k) => (acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined), obj);
      const n = typeof val === 'string' ? Number(val) : (val as number);
      if (Number.isFinite(n)) return n as number;
    } catch {
      /* fall through to form parsing */
    }
  }
  try {
    const params = new URLSearchParams(text);
    const all = params.getAll(field);
    // Duplicate keys are ambiguous: URLSearchParams.get() returns the FIRST value,
    // but Stripe/Rack/PHP/Rails take the LAST. Refuse to guess — fail closed.
    if (all.length > 1) return undefined;
    if (all.length === 1) {
      const n = Number(all[0]);
      if (Number.isFinite(n)) return n;
    }
  } catch {
    /* ignore */
  }
  return undefined;
}

/**
 * Why a read produced no number. `undefined` conflated two very different
 * answers - "there is no amount here" and "there IS one and I refuse to guess
 * which" - and the caller treated both as "keep looking". See [readAmount].
 */
export type AmountRead =
  | { kind: 'value'; value: number }
  | { kind: 'absent' }
  | { kind: 'refused'; why: string };

/**
 * Read the amount from the body, distinguishing absent from refused.
 *
 * [extractAmount] below returns `undefined` for both, which is what let the
 * cap be bypassed: a body of `amount=1&amount=999999` is a deliberate REFUSAL
 * (duplicate keys are ambiguous - URLSearchParams.get takes the first,
 * Stripe/Rack/PHP/Rails take the last), and evaluate() was then happy to accept
 * an attacker-supplied `?amount=1` from the query in its place.
 */
export function readAmount(body: Buffer | null, contentType: string | undefined, field: string): AmountRead {
  if (!body || !body.length) return { kind: 'absent' };
  const text = body.toString('utf8');
  const trimmed = text.replace(/^[﻿\s]+/, '');
  const ct = (contentType || '').toLowerCase();
  if (ct.includes('application/json') || trimmed[0] === '{' || trimmed[0] === '[') {
    try {
      const obj = JSON.parse(trimmed) as unknown;
      const val = field
        .split('.')
        .reduce<unknown>((acc, k) => (acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined), obj);
      const n = typeof val === 'string' ? Number(val) : (val as number);
      if (Number.isFinite(n)) return { kind: 'value', value: n as number };
      if (val !== undefined) return { kind: 'refused', why: `field '${field}' is present but not a finite number` };
    } catch {
      /* fall through to form parsing */
    }
  }
  try {
    const params = new URLSearchParams(text);
    const all = params.getAll(field);
    if (all.length > 1) return { kind: 'refused', why: `field '${field}' appears ${all.length} times; which one the upstream reads is ambiguous` };
    if (all.length === 1) {
      const n = Number(all[0]);
      if (Number.isFinite(n)) return { kind: 'value', value: n };
      return { kind: 'refused', why: `field '${field}' is present but not a finite number` };
    }
  } catch {
    /* ignore */
  }
  return { kind: 'absent' };
}

/**
 * Extract the amount from a URL query string.
 *
 * A dotted field is NOT collapsed to its last segment any more. `.pop()` meant a
 * cap on `transfer_data.amount` was satisfied by a top-level `?amount=`, which
 * is a different field the upstream would not read as that cap's subject. Only
 * the exact dotted spelling and the conventional bracket form are accepted.
 */
export function extractAmountFromQuery(pathWithQuery: string, field: string): number | undefined {
  const q = pathWithQuery.indexOf('?');
  if (q < 0) return undefined;
  try {
    const params = new URLSearchParams(pathWithQuery.slice(q + 1));
    const keys = field.includes('.')
      ? [field, field.split('.').reduce((a, b, i) => (i === 0 ? b : `${a}[${b}]`))]
      : [field];
    const all = keys.flatMap((k) => params.getAll(k));
    if (all.length !== 1) return undefined; // absent or ambiguous duplicate -> not readable
    const n = Number(all[0]);
    return Number.isFinite(n) ? n : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Read the amount from the URL query, mirroring readAmount's absent/refused/value
 * union so the query path fails CLOSED on an ambiguous duplicate exactly like the
 * body path. extractAmountFromQuery above conflated "absent" with "duplicate",
 * which let `?amount=1&amount=999999` slip the value the upstream honours
 * (last-wins) past the cap. Enforcement uses THIS; extractAmountFromQuery stays
 * only for display of an unambiguous single value.
 */
export function readAmountFromQuery(pathWithQuery: string, field: string): AmountRead {
  const q = pathWithQuery.indexOf('?');
  if (q < 0) return { kind: 'absent' };
  try {
    const params = new URLSearchParams(pathWithQuery.slice(q + 1));
    const keys = field.includes('.')
      ? [field, field.split('.').reduce((a, b, i) => (i === 0 ? b : `${a}[${b}]`))]
      : [field];
    const all = keys.flatMap((k) => params.getAll(k));
    if (all.length > 1) return { kind: 'refused', why: `field '${field}' appears ${all.length} times in the query; which one the upstream reads is ambiguous` };
    if (all.length === 1) {
      const n = Number(all[0]);
      if (Number.isFinite(n)) return { kind: 'value', value: n };
      return { kind: 'refused', why: `field '${field}' in the query is present but not a finite number` };
    }
    return { kind: 'absent' };
  } catch {
    return { kind: 'absent' };
  }
}

/** `/x/` -> `/x`; the root stays `/`. Matching only - never forwarded. */
function stripTrailingSlash(p: string): string {
  if (p.length <= 1) return p;
  const trimmed = p.replace(/\/+$/, '');
  return trimmed === '' ? '/' : trimmed;
}

/**
 * The resource an origin will actually resolve this path to, for MATCHING only.
 *
 * The request-target normaliser closed the wire-path transforms (dot-segments,
 * duplicate slashes, unreserved percent-decoding) and is used for forwarding, so
 * it may not alter what is sent. These are the remaining origin path-equivalences
 * that are NOT wire transforms and must never be forwarded, but which a rule for
 * the canonical resource has to see through or it is evaded by a spelling the
 * origin treats as the same endpoint. Each carried a real credential past a
 * path-scoped deny/amount/approval rule against the compiled build:
 *
 *   /v1/refunds;x=1     matrix parameters (Spring/JAX-RS strip them)
 *   /v1/refunds.        a trailing dot (Windows/IIS trim it)
 *   /v1/refunds%20      a trailing encoded space/tab/null
 *
 * Applied only to the value the matcher compares; the forwarded target keeps its
 * exact bytes, so this can over-match (fail-safe) but never rewrites a request.
 * Case is handled in matchPath, dot-segments in the normaliser.
 */
function originResourceForMatch(p: string): string {
  // Decode every escape whose byte the trailing-strip on the line below would
  // remove ([./\s\x00-\x1f]): all C0 controls (%00-%1F), space (%20), dot (%2e).
  // The two sets must mirror each other or an encoded control the strip would
  // otherwise remove — %0A/%0D/%0C/%0B and the rest of C0 — survives un-decoded
  // and evades the rule. %2F is intentionally excluded: the encoded-separator
  // equivalence is handled by originResourceDecodedSeparators.
  let s = p.replace(/%([01][0-9a-f]|20|2e)/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
  s = s.split('/').map((seg) => seg.split(';')[0]).join('/');
  s = s.replace(/[./\s\x00-\x1f]+$/, '');
  return s === '' ? '/' : s;
}

/** Interior dot-segment removal + duplicate-slash collapse, for the decoded form below. */
function resolveSegments(p: string): string {
  const out: string[] = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return '/' + out.join('/');
}

/**
 * The resource an origin that DECODES `%2F`/`%5C` in the path (Apache
 * `AllowEncodedSlashes`, some frameworks) resolves this to. MATCHING only,
 * fail-safe: adds a match the origin would honour; forwarded bytes stay encoded.
 */
function originResourceDecodedSeparators(p: string): string {
  if (!/%(2f|5c)/i.test(p)) return p;
  return originResourceForMatch(resolveSegments(p.replace(/%(2f|5c)/gi, '/')));
}

export class PolicyEngine {
  private buckets = new Map<string, number[]>();

  constructor(private policy: Policy) {}

  setPolicy(p: Policy): void {
    this.policy = p;
  }
  getPolicy(): Policy {
    return this.policy;
  }

  isHostAllowed(host: string): boolean {
    return matchAnyHost(this.policy.egressAllowlist, host);
  }

  private ruleMatches(rule: PolicyRule, ctx: EvalCtx): boolean {
    const hostOk = !rule.match.hosts?.length || matchAnyHost(rule.match.hosts, ctx.host);
    const rawPath = ctx.path.split('?')[0];
    // `/v1/refunds` and `/v1/refunds/` are the same endpoint to every API this
    // proxies, but they are different strings, so a deny rule written for one
    // was evaded by the other and fell through to the host-wide
    // `allow-secret-<name>` rule the product auto-creates. Verified against the
    // compiled build.
    //
    // This is fixed HERE and not in the request-target normaliser on purpose:
    // the normaliser rewrites what is forwarded upstream, and a trailing slash
    // genuinely can select a different resource there. Matching is the only
    // layer that may treat them as one.
    //
    // Additive by construction - the un-stripped form is tried first, so a
    // pattern like `/v1/refunds/*` that already matched still matches. Nothing
    // that was allowed becomes denied; only the evasion is closed.
    const pathOk =
      matchAnyPath(rule.match.paths, rawPath) ||
      matchAnyPath(rule.match.paths, stripTrailingSlash(rawPath)) ||
      matchAnyPath(rule.match.paths, originResourceForMatch(rawPath)) ||
      matchAnyPath(rule.match.paths, originResourceDecodedSeparators(rawPath));
    const methodOk =
      !rule.match.methods?.length ||
      rule.match.methods.map((m) => m.toUpperCase()).includes(ctx.method.toUpperCase());
    return hostOk && pathOk && methodOk;
  }

  /** Charge a slot against a rule's rate limit post-decision (e.g. after approval). */
  consumeRateForRule(ruleId: string, rl: RateLimit): boolean {
    return this.consumeRate(ruleId, rl.max, rl.windowSec);
  }

  /** Sliding-window rate check. Returns true if the request is within budget (and consumes a slot). */
  private consumeRate(ruleId: string, max: number, windowSec: number): boolean {
    // Fail closed on a misconfigured limit (e.g. windowSec<=0 would otherwise be "unlimited").
    if (!(windowSec > 0) || !(max >= 1)) return false;
    const now = Date.now();
    const windowMs = windowSec * 1000;
    const arr = (this.buckets.get(ruleId) || []).filter((t) => now - t < windowMs);
    if (arr.length >= max) {
      this.buckets.set(ruleId, arr);
      return false;
    }
    arr.push(now);
    this.buckets.set(ruleId, arr);
    return true;
  }

  evaluate(ctx: EvalCtx): PolicyDecision {
    if (!this.isHostAllowed(ctx.host)) {
      return { action: 'deny', reason: `host '${ctx.host}' is not on the egress allowlist (deny-by-default)` };
    }
    for (const rule of this.policy.rules) {
      if (!this.ruleMatches(rule, ctx)) continue;

      if (rule.amountLimit) {
        const field = rule.amountLimit.field;
        const max = rule.amountLimit.max;
        // Distinguish "there is no amount here" from "there IS one and I refuse
        // to guess which". Conflating those is what let the cap be bypassed: a
        // body of `amount=1&amount=999999` is ambiguous by construction
        // (URLSearchParams.get takes the first; Stripe/Rack/PHP/Rails take the
        // last), and treating that as absent meant an attacker-supplied
        // `?amount=1` was accepted in its place.
        const fromBody = readAmount(ctx.body, ctx.contentType, field);
        if (fromBody.kind === 'refused') {
          return {
            action: 'deny',
            ruleId: rule.id,
            reason: `amount cap on '${field}' could not be read from the request: ${fromBody.why} (deny-by-default)`,
          };
        }
        const amtBody = fromBody.kind === 'value' ? fromBody.value : undefined;
        const fromQuery = readAmountFromQuery(ctx.path, field);
        if (fromQuery.kind === 'refused') {
          return {
            action: 'deny',
            ruleId: rule.id,
            reason: `amount cap on '${field}' could not be read from the request: ${fromQuery.why} (deny-by-default)`,
          };
        }
        const amtQuery = fromQuery.kind === 'value' ? fromQuery.value : undefined;
        if (amtBody !== undefined && amtQuery !== undefined && amtQuery !== amtBody) {
          // Both readable and disagreeing: which one the upstream honours is
          // exactly the ambiguity this cap exists to remove.
          return {
            action: 'deny',
            ruleId: rule.id,
            reason: `amount cap on '${field}' is ambiguous: body says ${amtBody}, query says ${amtQuery} (deny-by-default)`,
          };
        }
        // Enforce the cap against EVERY location the upstream might read the
        // amount from. A within-cap value in one must NOT short-circuit, and so
        // mask, an over-cap value in the other.
        for (const amt of [amtBody, amtQuery]) {
          if (amt !== undefined && (amt < 0 || amt > max)) {
            return {
              action: 'deny',
              ruleId: rule.id,
              reason: `amount ${amt} is outside the allowed range [0, ${max}] on field '${field}'`,
            };
          }
        }
        if (amtBody === undefined && amtQuery === undefined) {
          // No readable amount in either location. Fail closed for any request that
          // could carry one — a non-empty body (incl. unparseable encodings, top-level
          // arrays/primitives, non-numeric values) or a mutating method — so the hard
          // ceiling can't be bypassed by hiding/omitting the amount. (Bodyless GET/HEAD:
          // nothing to cap.)
          const mutating = ['POST', 'PUT', 'PATCH'].includes(ctx.method.toUpperCase());
          if ((ctx.body && ctx.body.length) || mutating) {
            return {
              action: 'deny',
              ruleId: rule.id,
              reason: `amount cap on '${field}' could not be read from the request (deny-by-default)`,
            };
          }
        }
      }

      // Deny-by-default for an unrecognized rule action (typo/hand-edit/bad producer):
      // a malformed action must never fall through to allow + credential injection.
      const safeAction: PolicyAction =
        rule.action === 'allow' || rule.action === 'require_approval' ? rule.action : 'deny';

      if (safeAction === 'allow' && rule.rateLimit) {
        const ok = this.consumeRate(rule.id, rule.rateLimit.max, rule.rateLimit.windowSec);
        if (!ok) {
          return {
            action: 'deny',
            ruleId: rule.id,
            reason: `rate limit exceeded (${rule.rateLimit.max}/${rule.rateLimit.windowSec}s)`,
          };
        }
      }

      return {
        action: safeAction,
        ruleId: rule.id,
        reason: safeAction === rule.action ? `matched rule '${rule.id}'` : `matched rule '${rule.id}' (unrecognized action -> deny)`,
      };
    }
    return { action: this.policy.defaultAction, reason: 'no matching rule (deny-by-default)' };
  }
}
