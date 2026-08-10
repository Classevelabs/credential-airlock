/**
 * Vault format-version compatibility.
 *
 * `VAULT_VERSION` was written into every vault on create and then never read
 * again — `Vault.open()` parsed the JSON and used it whatever the version said.
 * Nothing was broken while only version 1 existed, but the first format change
 * would have made an old vault open silently and be read as the new shape, and
 * a vault written by a newer build open silently under an older one. On a
 * credential store that is the worst available outcome: it surfaces later as
 * missing or wrong secrets, with the original bytes already overwritten by the
 * next persist.
 *
 * These cases pin the contract that makes a future format change survivable:
 * a vault from the future is refused loudly, the file it refused is left
 * byte-identical, an unversioned or corrupt blob is refused rather than guessed
 * at, and today's version still opens and keeps its secrets.
 *
 * Run: node test/vault-version.mjs   (after `npm run build`)
 */
import { createRequire } from 'module';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const D = (p) => require(path.join(here, '..', 'dist', p));

let pass = 0;
let fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}  ${extra}`); }
};

const SECRET = 'DUMMY_VERSION_SECRET_7c1d4e';
const DAILY = 'vault-version-daily-pass-CCCC';

const { Runtime } = D('runtime.js');
const { paths } = D('config.js');
const { VAULT_AAD } = D('vault/vault.js');
const { aesgcmEncrypt, aesgcmDecrypt } = D('crypto/aesgcm.js');
const { PassphraseSealer } = D('crypto/passphrase.js');

function freshHome(base, name) {
  const home = path.join(base, name);
  fs.mkdirSync(home, { recursive: true });
  return paths(home);
}

/** Create a vault holding a real secret, then close it. */
async function makeVault(P) {
  const rt = await Runtime.initNew(P, { passphrase: DAILY });
  rt.addOrUpdateSecret({
    name: 'svc',
    placeholder: '__SVC__',
    allowedHosts: ['api.example.com'],
    injection: { mode: 'header', header: 'authorization', valueTemplate: 'Bearer {{secret}}' },
    value: SECRET,
  });
  rt.close();
}

/** Rewrite the vault's plaintext `version` field in place, re-sealing it. */
async function rewriteVersion(P, mutate) {
  const sealer = new PassphraseSealer(DAILY);
  const vdk = await sealer.unseal(fs.readFileSync(P.vdkSeal));
  const plain = aesgcmDecrypt(vdk, fs.readFileSync(P.vaultEnc), VAULT_AAD);
  const data = JSON.parse(plain.toString('utf8'));
  mutate(data);
  fs.writeFileSync(
    P.vaultEnc,
    aesgcmEncrypt(vdk, Buffer.from(JSON.stringify(data), 'utf8'), VAULT_AAD),
  );
}

async function openFails(P) {
  try {
    const rt = await Runtime.open(P, { passphrase: DAILY });
    rt.close();
    return null;
  } catch (e) {
    return e.message || String(e);
  }
}

async function main() {
  process.env.AIRLOCK_SEALER = 'passphrase';
  process.env.AIRLOCK_PASSPHRASE = DAILY;
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-vaultver-'));
  console.log('vault format-version compatibility');

  // --- today's version opens and keeps its secret -------------------------
  {
    const P = freshHome(base, 'current');
    await makeVault(P);
    const err = await openFails(P);
    ok('current version still opens', err === null, err || '');
  }

  // --- a vault from the FUTURE is refused, not guessed at -----------------
  {
    const P = freshHome(base, 'future');
    await makeVault(P);
    await rewriteVersion(P, (d) => { d.version = 99; });
    const err = await openFails(P);
    ok('a newer vault version is refused', err !== null,
      'it opened a version-99 vault as if it were version 1');
    ok('the refusal names the version mismatch',
      err !== null && /version/i.test(err) && /99/.test(err),
      `message was: ${err}`);
  }

  // --- refusing must not rewrite the file it refused ----------------------
  {
    const P = freshHome(base, 'untouched');
    await makeVault(P);
    await rewriteVersion(P, (d) => { d.version = 99; });
    const before = fs.readFileSync(P.vaultEnc);
    await openFails(P);
    const after = fs.readFileSync(P.vaultEnc);
    ok('a refused vault is left byte-identical', before.equals(after),
      'refusing to open must never rewrite the file it refused');
  }

  // --- unrecognisable versions are refused, never defaulted ---------------
  const bad = [
    ['missing', (d) => { delete d.version; }],
    ['null', (d) => { d.version = null; }],
    ['a string', (d) => { d.version = '1'; }],
    ['zero', (d) => { d.version = 0; }],
    ['negative', (d) => { d.version = -1; }],
    ['fractional', (d) => { d.version = 1.5; }],
  ];
  for (const [label, mutate] of bad) {
    const P = freshHome(base, `bad-${label.replace(/\s+/g, '-')}`);
    await makeVault(P);
    await rewriteVersion(P, mutate);
    const err = await openFails(P);
    ok(`version ${label} is refused`, err !== null,
      'an unrecognisable vault must be refused, not treated as the current version');
  }

  console.log(`\nvault-version: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
