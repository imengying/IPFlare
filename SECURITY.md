# Security Policy

## Supported Versions

Only the latest GitHub Release receives security fixes. Upgrade to the newest
release before reporting a vulnerability.

## Reporting a Vulnerability

Do not open a public issue for a security vulnerability. Use
[GitHub Private Vulnerability Reporting](https://github.com/imengying/IPFlare/security/advisories/new)
or contact the maintainer privately through the address on their GitHub profile.

Include the affected version, impact, reproduction steps, and any suggested
mitigation. Reports are normally acknowledged within 72 hours.

## API Token Handling

- Create a scoped Cloudflare API token with only the permissions and zones the
  application needs. Do not use a Global API Key.
- Keep `config.json` readable only by the account running the application.
- Never commit a real `config.json`; it is excluded by `.gitignore`.
- All Cloudflare API and network-provider requests use HTTPS.

## Supply Chain

Dependencies are locked in `Cargo.lock`. Version tags trigger native builds on
GitHub-hosted runners, and release archives include SHA-256 checksums.

## Scope

Authentication flaws, token exposure, configuration injection, DNS record
hijacking, and exploitable dependency vulnerabilities are in scope. Cloudflare
platform vulnerabilities should be reported directly to Cloudflare.
