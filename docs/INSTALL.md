# Install Credential Airlock

Credential Airlock ships as a Node CLI named `airlock`.

Requirements:

- Node.js 20 or newer.
- Windows 11 for the default DPAPI sealer, or Linux/macOS with the passphrase
  sealer configured for service deployments.
- A local user account you trust. The vault is sealed for the local operator,
  not for a remote SaaS service.

## Install From GitHub

This path builds from source through the package `prepare` script. It requires
the repository to be public, or your npm/git process to have GitHub credentials.

```powershell
npm install -g github:Classevelabs/credential-airlock
airlock doctor
```

## Install From A Release Tarball

Use this for offline machines or pinned internal rollout:

```powershell
$version = "0.1.1"
$url = "https://github.com/classeve-public/credential-airlock/releases/download/v$version/credential-airlock-$version.tgz"
Invoke-WebRequest $url -OutFile ".\credential-airlock-$version.tgz"
npm install -g ".\credential-airlock-$version.tgz"
airlock doctor
```

The release workflow publishes the same packed artifact to GitHub Releases. It
also publishes to npm when repository npm publishing credentials are configured.

## First Boot

```powershell
airlock doctor
airlock init

$secret = Read-Host "OpenAI key"
$secret | airlock secret set openai --stdin --host api.openai.com
Remove-Variable secret

airlock start
```

Open your agent through `airlock run -- <command>` or from the local control
panel. The agent sees placeholders; Credential Airlock injects the real key only
toward the hosts bound to that secret.

## Verify An Install

```powershell
airlock doctor
airlock status
airlock health --deep
airlock audit --verify
```

For maintainers, `npm run smoke:install` packs the current tree, installs the
tarball into a temporary npm prefix, and runs the installed `airlock` binary.
