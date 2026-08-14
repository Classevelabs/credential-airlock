/**
 * Request-target normalisation for the policy trust boundary.
 *
 * THE DEFECT THIS CLOSES. `proxy.ts` took the request-target verbatim off the
 * intercepted TLS stream (`path = req.url || '/'`) and used that exact string
 * both to evaluate policy and to forward upstream. Node exposes whatever the
 * client wrote, so the proxy's view of "which resource is this" and the
 * origin's view could differ. Every spelling below was verified against the
 * compiled build to evade a path-scoped deny rule and land in the host-wide
 * `allow-secret-<name>` rule that `maintainPolicyForSecret` auto-creates on
 * every `secret set` — with the real credential injected:
 *
 *   POST https://api.example.com/v1/refunds   absolute-form, matches no `/v1/...` rule
 *   /v1/refunds/                              trailing slash
 *   //v1/refunds                              duplicate slash
 *   /v1/%72efunds                             percent-encoded unreserved character
 *   /v1/./refunds                             dot-segment
 *   /v1/x/../refunds                          dot-dot-segment
 *
 * "Deny by default" does not save any of them: the fall-through target is an
 * allow rule the product generates for the operator.
 *
 * THE INVARIANT. The proxy must evaluate policy against the same resource the
 * origin will serve. So the normalised form is used for BOTH matching and
 * forwarding — normalising only for matching would leave the two views split
 * in the other direction.
 *
 * WHY FORWARDING THE NORMALISED FORM IS SAFE. Every transform here is one the
 * origin server performs itself, per RFC 3986:
 *   - dot-segment removal is §5.2.4, mandatory during reference resolution;
 *   - decoding percent-escapes of UNRESERVED characters is §6.2.2.2, defined as
 *     producing an equivalent URI;
 *   - duplicate-slash collapsing is what every mainstream router does.
 * Reserved characters stay encoded, so `%2F` is never turned into a real
 * separator and an encoded slash cannot gain path structure it did not have.
 *
 * WHAT IS DELIBERATELY NOT DONE HERE. A trailing slash is NOT stripped:
 * `/orders` and `/orders/` are genuinely different resources to many APIs, and
 * rewriting one into the other would change what the upstream receives. That
 * spelling is handled where it belongs — as an equivalence in the policy
 * matcher, which never touches the forwarded request.
 */

/** Unreserved set, RFC 3986 §2.3. Safe to decode; never changes meaning. */
function isUnreserved(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) || // A-Z
    (code >= 0x61 && code <= 0x7a) || // a-z
    (code >= 0x30 && code <= 0x39) || // 0-9
    code === 0x2d || code === 0x2e || code === 0x5f || code === 0x7e // - . _ ~
  );
}

/**
 * Decode `%XX` only where XX is an unreserved character, and uppercase every
 * escape that remains. Both are RFC 3986 §6.2.2 normalisations that preserve
 * meaning, and together they mean `/v1/%72efunds`, `/v1/%72EFUNDS` and
 * `/v1/refunds` can no longer be three different strings to the matcher.
 */
function normalizePercentEncoding(segment: string): string {
  let out = '';
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (ch !== '%') {
      out += ch;
      continue;
    }
    const hex = segment.slice(i + 1, i + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
      // A stray '%' is not a valid escape. Leave it; the caller rejects
      // malformed targets separately rather than guessing an intent.
      out += ch;
      continue;
    }
    const code = parseInt(hex, 16);
    out += isUnreserved(code) ? String.fromCharCode(code) : '%' + hex.toUpperCase();
    i += 2;
  }
  return out;
}

/** Remove `.` and `..` segments. RFC 3986 §5.2.4, without the buffer dance. */
function removeDotSegments(pathname: string): string {
  const out: string[] = [];
  for (const segment of pathname.split('/')) {
    if (segment === '.') continue;
    if (segment === '..') {
      // Never climb above the root: a `..` at the top is dropped, matching
      // what §5.2.4 does and what origin servers do.
      out.pop();
      continue;
    }
    out.push(segment);
  }
  let joined = out.join('/');
  if (!joined.startsWith('/')) joined = '/' + joined;
  return joined;
}

export interface NormalizedTarget {
  /** Path plus query, normalised. Use for policy AND for forwarding. */
  target: string;
  /** Path only, normalised. */
  pathname: string;
  /** Query including '?', or ''. Passed through untouched. */
  query: string;
}

export class InvalidRequestTarget extends Error {}

/**
 * Normalise an origin-form request-target.
 *
 * Absolute-form (`https://host/path`) and authority-form (`host:port`) are
 * REJECTED rather than rewritten. Through an established CONNECT tunnel the
 * target must be origin-form or asterisk-form (RFC 7230 §5.3), so absolute-form
 * arriving there is either a broken client or an attempt to describe a
 * different resource to the proxy than to the origin. Rewriting it would mean
 * guessing which; refusing it is the only answer that cannot be wrong.
 *
 * @throws InvalidRequestTarget
 */
export function normalizeRequestTarget(raw: string | undefined): NormalizedTarget {
  const value = raw && raw.length > 0 ? raw : '/';

  // Asterisk-form: only ever valid for OPTIONS, and carries no path to match.
  if (value === '*') return { target: '*', pathname: '*', query: '' };

  if (value.includes('\0') || /[\r\n]/.test(value)) {
    throw new InvalidRequestTarget('request target contains control characters');
  }
  if (!value.startsWith('/')) {
    throw new InvalidRequestTarget(
      'request target must be origin-form; absolute-form and authority-form are refused inside a proxy tunnel'
    );
  }
  // `//host/path` is a protocol-relative reference, not a path with a doubled
  // slash, and some clients and servers read it as an authority. Refuse the
  // ambiguity rather than pick a reading — but only when it actually looks like
  // an authority, so an ordinary `//v1/x` typo is still just collapsed below.
  if (/^\/\/[^/]/.test(value) && /^\/\/[^/]*[.:@]/.test(value)) {
    throw new InvalidRequestTarget('request target is protocol-relative; origin-form required');
  }

  const queryAt = value.indexOf('?');
  const rawPath = queryAt === -1 ? value : value.slice(0, queryAt);
  const query = queryAt === -1 ? '' : value.slice(queryAt);

  let pathname = normalizePercentEncoding(rawPath);
  pathname = removeDotSegments(pathname);
  // Collapse runs of slashes. Done AFTER dot-segment removal so `/a/.//b` and
  // `/a//b` converge, and after decoding so `/a/%2F/b` does not: `%2F` is
  // reserved and stays encoded, which is the point.
  pathname = pathname.replace(/\/{2,}/g, '/');
  if (pathname === '') pathname = '/';

  return { target: pathname + query, pathname, query };
}
