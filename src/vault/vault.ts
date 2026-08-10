/**
 * The vault: secret storage sealed at rest, decrypted only in proxy memory.
 *
 * Key invariant — there is NO reveal path. listSecrets() returns metadata with
 * values stripped. getSecretValue()/getInjectors() exist for in-process injection
 * only and are never wired to the admin API.
 */
import { Paths } from '../config';
import { Sealer, VaultData, SecretMeta, SecretWithValue, InjectionSpec } from '../types';
import { aesgcmEncrypt, aesgcmDecrypt, randomKey } from '../crypto/aesgcm';
import { atomicWrite, readFileOpt, exists } from '../util/fsx';
import { registerRedaction, clearRedactions } from '../util/logger';
import { assertInjectableSecret } from '../util/secret-validate';
import { generateCA, CaMaterial } from '../ca/ca';

export const VAULT_AAD = Buffer.from('credential-airlock/vault/v1', 'utf8');
const VAULT_VERSION = 1;

export interface Injector {
  name: string;
  value: string;
  allowedHosts: string[];
  injection: InjectionSpec;
  placeholder: string;
}

/**
 * A vault is only openable if this build understands its format.
 *
 * `version` was written on create and then never read, so any future format
 * change would have been silent: an old vault would open and be interpreted as
 * the new shape, and a vault written by a newer build would open under an older
 * one. On a credential store that is the worst failure mode available — nothing
 * throws, the misreading is persisted by the next write, and the original bytes
 * are gone.
 *
 * Refusing is the safe answer in both directions. A vault from the future can
 * only be handled by the build that wrote it; a vault with no recognisable
 * version is not a vault this code should be guessing about. Older versions
 * would be migrated here — none exist yet, and when the first one does, this is
 * the single place that has to learn about it.
 *
 * Throws without touching the file: the caller must be able to downgrade,
 * restore a backup, or upgrade and try again against untouched bytes.
 */
function assertOpenableVersion(data: VaultData | null | undefined): void {
  const v = data?.version;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1) {
    throw new Error(
      'vault.enc is not a recognisable vault: its format version is missing or invalid. ' +
      'Refusing to open rather than guess at the layout of a credential store. ' +
      'Restore from a backup (`airlock backup restore`) or re-run `airlock init` on a fresh data directory.',
    );
  }
  if (v > VAULT_VERSION) {
    throw new Error(
      `this vault was written by a newer credential-airlock (vault format version ${v}; ` +
      `this build understands up to ${VAULT_VERSION}). Refusing to open it — reading a newer ` +
      'format as an older one would silently corrupt your secrets on the next write. ' +
      'Upgrade credential-airlock to the version that wrote this vault.',
    );
  }
  // v < VAULT_VERSION: no older format exists yet. When one does, migrate here
  // — and write the migration so it is reversible before it persists anything.
}

export class Vault {
  private constructor(
    private readonly p: Paths,
    private vdk: Buffer,
    private data: VaultData
  ) {}

  // --- lifecycle ----------------------------------------------------------
  static async create(p: Paths, sealer: Sealer): Promise<Vault> {
    // Never clobber an existing vault — the only safe creation is a fresh one.
    if (exists(p.vaultEnc) || exists(p.vdkSeal)) {
      throw new Error('refusing to create: a vault already exists at this location');
    }
    const vdk = randomKey();
    const ca = generateCA();
    const data: VaultData = {
      version: VAULT_VERSION,
      createdAt: new Date().toISOString(),
      secrets: {},
      ca,
      meta: {},
    };
    const v = new Vault(p, vdk, data);
    const sealed = await sealer.seal(vdk); // may throw — seal BEFORE writing any file
    v.persistVault();
    atomicWrite(p.vdkSeal, sealed);
    v.registerAllRedactions(); // register the CA key for redaction from first run
    return v;
  }

  static async open(p: Paths, sealer: Sealer): Promise<Vault> {
    const sealedVdk = readFileOpt(p.vdkSeal);
    if (!sealedVdk) throw new Error('vdk.seal not found — run `airlock init` first');
    const enc = readFileOpt(p.vaultEnc);
    if (!enc) throw new Error('vault.enc not found — run `airlock init` first');
    const vdk = await sealer.unseal(sealedVdk);
    const plain = aesgcmDecrypt(vdk, enc, VAULT_AAD);
    let data: VaultData;
    try {
      data = JSON.parse(plain.toString('utf8')) as VaultData;
    } finally {
      plain.fill(0); // minimize how long the decrypted vault lives in memory
    }
    assertOpenableVersion(data);
    const v = new Vault(p, vdk, data);
    v.registerAllRedactions();
    return v;
  }

  close(): void {
    if (this.vdk) this.vdk.fill(0);
    clearRedactions();
  }

  // --- persistence --------------------------------------------------------
  private persistVault(): void {
    const plain = Buffer.from(JSON.stringify(this.data), 'utf8');
    const blob = aesgcmEncrypt(this.vdk, plain, VAULT_AAD);
    atomicWrite(this.p.vaultEnc, blob);
    plain.fill(0);
  }

  private registerAllRedactions(): void {
    for (const s of Object.values(this.data.secrets)) registerRedaction(s.value);
    // The CA private key is a universal-MITM secret — scrub it from logs/responses too.
    if (this.data.ca?.keyPem) registerRedaction(this.data.ca.keyPem);
  }

  /** Re-encrypt the vault under a new VDK and reseal it (used by migration). */
  async rekey(newVdk: Buffer, sealer: Sealer): Promise<void> {
    const sealed = await sealer.seal(newVdk); // may throw — seal BEFORE re-encrypting; old state stays openable
    const old = this.vdk;
    this.vdk = newVdk;
    this.persistVault();
    atomicWrite(this.p.vdkSeal, sealed);
    if (old && old !== newVdk) old.fill(0); // wipe the superseded key
  }

  // --- secrets (WRITE-ONLY; no reveal) -----------------------------------
  setSecret(meta: Omit<SecretMeta, 'createdAt' | 'updatedAt'>, value: string): void {
    if (!value) throw new Error('secret value must not be empty');
    // Reject up front a secret that could not be injected cleanly (control chars /
    // >0xFF in a header-bound value, invalid header name, lone surrogate). Sealing
    // such a value yields a credential that 502-black-holes — or CRLF-smuggles —
    // at forward time. This is the single chokepoint every write path funnels
    // through (CLI, admin API), so all of them inherit the check.
    assertInjectableSecret(value, meta.injection, meta.placeholder);
    const now = new Date().toISOString();
    const existing = this.data.secrets[meta.name];
    const record: SecretWithValue = {
      ...meta,
      value,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      lastRotatedAt: existing ? now : undefined,
    };
    this.data.secrets[meta.name] = record;
    this.persistVault();
    registerRedaction(value);
  }

  rotateSecret(name: string, newValue: string): void {
    const s = this.data.secrets[name];
    if (!s) throw new Error(`no such secret: ${name}`);
    // Same injectability gate as setSecret, against the EXISTING secret's
    // injection spec/placeholder (rotation only changes the value).
    assertInjectableSecret(newValue, s.injection, s.placeholder);
    s.value = newValue;
    s.lastRotatedAt = new Date().toISOString();
    s.updatedAt = s.lastRotatedAt;
    this.persistVault();
    registerRedaction(newValue);
  }

  deleteSecret(name: string): void {
    if (!this.data.secrets[name]) throw new Error(`no such secret: ${name}`);
    delete this.data.secrets[name];
    this.persistVault();
  }

  /** Metadata only — values are stripped. Safe for the admin API. */
  listSecrets(): SecretMeta[] {
    return Object.values(this.data.secrets).map((s) => {
      const { value, ...meta } = s;
      void value;
      return meta;
    });
  }

  hasSecret(name: string): boolean {
    return !!this.data.secrets[name];
  }

  // --- in-process only (proxy injection) ---------------------------------
  /** INTERNAL: returns injectors with real values. Never exposed via the API. */
  getInjectors(): Injector[] {
    return Object.values(this.data.secrets).map((s) => ({
      name: s.name,
      value: s.value,
      allowedHosts: s.allowedHosts,
      injection: s.injection,
      placeholder: s.placeholder,
    }));
  }

  // --- CA -----------------------------------------------------------------
  getCA(): CaMaterial {
    if (!this.data.ca) {
      this.data.ca = generateCA();
      this.persistVault();
    }
    return this.data.ca;
  }

  get caCertPem(): string {
    return this.getCA().certPem;
  }
}
