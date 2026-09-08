/**
 * Tiny, dependency-free glob matcher for host and path patterns.
 *  - `*`  matches any run of characters
 *  - `?`  matches a single character
 * Everything else is matched literally. Hosts are matched case-insensitively.
 *
 * Security note: prefer exact patterns. `*.stripe.com` compiles to an anchored
 * regex requiring a literal `.stripe.com` suffix, so `evil-stripe.com` does NOT
 * match. Patterns are always fully anchored (^...$).
 */
const cache = new Map<string, RegExp>();

function compile(pattern: string, flags: string): RegExp {
  const key = flags + ' ' + pattern;
  const hit = cache.get(key);
  if (hit) return hit;
  let re = '^';
  for (const ch of pattern) {
    if (ch === '*') re += '.*';
    else if (ch === '?') re += '.';
    else re += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  re += '$';
  const compiled = new RegExp(re, flags);
  cache.set(key, compiled);
  return compiled;
}

export function matchHost(pattern: string, host: string): boolean {
  return compile(pattern, 'i').test(host);
}

export function matchPath(pattern: string, p: string): boolean {
  // Case-INSENSITIVE, like matchHost. A path rule guards a resource, and many
  // origins the proxy fronts resolve paths case-insensitively (IIS/.NET, most
  // CDNs), so a case-sensitive matcher let `/V1/REFUNDS` slip a deny/cap/approval
  // rule written for `/v1/refunds` and still reach the same resource upstream.
  // Folding case only ever widens what a rule matches, never what is forwarded.
  return compile(pattern, 'i').test(p);
}

export function matchAnyHost(patterns: string[] | undefined, host: string): boolean {
  if (!patterns || patterns.length === 0) return false;
  return patterns.some((p) => matchHost(p, host));
}

export function matchAnyPath(patterns: string[] | undefined, p: string): boolean {
  if (!patterns || patterns.length === 0) return true; // no path constraint => any path
  return patterns.some((pat) => matchPath(pat, p));
}
