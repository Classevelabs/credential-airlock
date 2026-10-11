/**
 * Airlock makes keys and signs certificates with node-forge. It never asks
 * forge to verify a signature.
 *
 * That sentence is the reason audit-exceptions.json gives for carrying an
 * advisory on forge's RSA signature verification, so it has to be something a
 * run can fail, not something a reviewer remembers. It is held twice, because
 * each half misses what the other catches:
 *
 *   - by reading: forge is imported in one file, and every forge member that
 *     file touches is on the list below. A new member fails here until someone
 *     decides whether it verifies anything.
 *   - by running: every RSA public key forge creates is given a tripwire on its
 *     verify(), then a CA is generated and certificates are minted the way the
 *     proxy does it. The tripwire must stay silent, and must be shown to fire.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');

let pass = 0;
let fail = 0;
function ok(label, cond, extra) {
  if (cond) { pass++; console.log(`  PASS  ${label}`); }
  else { fail++; console.log(`  FAIL  ${label}${extra ? '  ' + extra : ''}`); }
}

console.log('\nforge-surface: what Airlock asks node-forge to do');

function filesUnder(dir, ext) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesUnder(full, ext));
    else if (entry.name.endsWith(ext)) out.push(full);
  }
  return out;
}
const rel = (file) => path.relative(root, file).replaceAll('\\', '/');
const withoutComments = (text) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

// --- by reading -------------------------------------------------------------
const importers = filesUnder(path.join(root, 'src'), '.ts')
  .filter((file) => /from\s+['"]node-forge['"]|require\(\s*['"]node-forge['"]\s*\)/.test(fs.readFileSync(file, 'utf8')))
  .map(rel);
ok('one source file imports node-forge', importers.length === 1 && importers[0] === 'src/ca/ca.ts', `(found ${importers.join(', ') || 'none'})`);

const shipped = filesUnder(path.join(root, 'dist'), '.js')
  .filter((file) => /require\(\s*['"]node-forge['"]\s*\)/.test(fs.readFileSync(file, 'utf8')))
  .map(rel);
ok('one shipped file loads node-forge', shipped.length === 1 && shipped[0] === 'dist/ca/ca.js', `(found ${shipped.join(', ') || 'none'})`);

// Random bytes, hex, a SHA-256 digest to sign over, RSA key generation,
// building a certificate, and PEM in and out. None of them checks a signature.
const ALLOWED = new Set([
  'forge.pki',
  'forge.random.getBytesSync',
  'forge.util.bytesToHex',
  'forge.md.sha256.create',
  'forge.pki.Certificate',
  'forge.pki.CertificateField',
  'forge.pki.rsa.PrivateKey',
  'forge.pki.rsa.KeyPair',
  'pki.rsa.generateKeyPair',
  'pki.createCertificate',
  'pki.certificateToPem',
  'pki.certificateFromPem',
  'pki.privateKeyToPem',
  'pki.privateKeyFromPem',
  'pki.publicKeyToPem',
]);
const code = withoutComments(fs.readFileSync(path.join(root, 'src', 'ca', 'ca.ts'), 'utf8'));
const touched = [...new Set(code.match(/\b(?:forge|pki)(?:\.[A-Za-z_$][\w$]*)+/g) ?? [])].sort();
ok('the file reaches into forge at all (the reader below is looking at something)', touched.length >= 10, `(found ${touched.length})`);
for (const member of touched) {
  ok(`known, non-verifying member: ${member}`, ALLOWED.has(member));
}
ok('nothing in that file is named verify', !/verif/i.test(code));
ok('no forge trust store, TLS, PKCS#7 or SSH in that file', !/caStore|forge\.tls|forge\.pkcs7|forge\.ssh/i.test(code));

// --- by running -------------------------------------------------------------
// Every RSA public key forge makes comes out of this one function, under two
// names it looks up at call time; x509 verification ends in the key's verify().
const forge = require('node-forge');
let verifyCalls = 0;
const makeKey = forge.pki.rsa.setPublicKey;
ok('forge still makes public keys in one place', typeof makeKey === 'function' && forge.pki.setRsaPublicKey === makeKey);
const tripwired = function (...args) {
  const key = makeKey.apply(this, args);
  const verify = key.verify;
  key.verify = function (...rest) {
    verifyCalls++;
    return verify.apply(this, rest);
  };
  return key;
};
forge.pki.rsa.setPublicKey = tripwired;
forge.pki.setRsaPublicKey = tripwired;

const { generateCA, CertAuthority } = require(path.join(root, 'dist', 'ca', 'ca.js'));
const material = generateCA();
const authority = new CertAuthority(material);
authority.contextFor('api.example.test');
authority.contextFor('127.0.0.1');
authority.contextFor('api.example.test');
ok('a CA and its leaf certificates are made without one forge verify', verifyCalls === 0, `(${verifyCalls} calls)`);

// The tripwire has to be able to fire, or the line above proves nothing.
const ca = forge.pki.certificateFromPem(material.certPem);
ok('the tripwire fires when forge is asked to verify', ca.verify(ca) === true && verifyCalls === 1, `(${verifyCalls} calls)`);

console.log(`\nforge-surface: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
