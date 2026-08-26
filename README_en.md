# ipflare

[中文](README.md) | English

A small Rust client that updates Cloudflare A/AAAA records and WAF IP lists
when the public IP address changes.

## Features

- IPv4 and IPv6 with independent detection providers
- Multiple domains in one Cloudflare zone, wildcard records, and IDN domains
- Cloudflare WAF IP list synchronization
- Proxied-record expressions and managed-record comment filters
- Optional Telegram notifications
- One-shot or interval-based execution
- Dry-run mode and graceful shutdown cleanup
- Rejection of Cloudflare anycast addresses

## Install

### Linux one-line installer

The installer is portable across Linux x86_64 and aarch64. It uses POSIX `sh`,
supports `curl` or `wget`, and detects systemd or OpenRC automatically. It
installs these files:

```text
/etc/ipflare/ipflare
/etc/ipflare/config.json
```

With `curl`:

```sh
curl -fsSL https://raw.githubusercontent.com/imengying/IPFlare/main/install.sh | sudo sh
```

Use `wget` when `curl` is unavailable:

```sh
wget -qO- https://raw.githubusercontent.com/imengying/IPFlare/main/install.sh | sudo sh
```

Omit `sudo` when already running as root.

The required prompts cover the Cloudflare API Token, Account ID, Zone ID,
domain, and IPv4/IPv6 switches. Proxy mode, update interval, WAF, and Telegram
are grouped under the optional "Other options" prompt. IPv4 is enabled by
default and IPv6 is disabled; disabling an address family also disables its
public IP lookup.

Run the installer again to open its update, reconfiguration, and uninstall
menu. Updates preserve the configuration, and uninstall removes `config.json`
only after explicit confirmation. No separate local management command is
installed.

### Release files

Each GitHub Release archive contains only the executable. Builds are published
for:

- Linux x86_64 and aarch64 (static musl binaries, including Alpine)
- macOS Apple Silicon
- Windows x86_64

To build from source:

```bash
cargo build --release --locked
```

## Configuration

The application reads only `config.json` from its current working directory.
Environment variables and older configuration schemas are not supported.
Unknown fields are rejected.

Create a configuration from the repository example:

```bash
cp config-example.json config.json
```

Minimal configuration:

```json
{
  "api_token": "your-cloudflare-api-token",
  "account_id": "11111111111111111111111111111111",
  "zone_id": "22222222222222222222222222222222",
  "domains": ["home.example.com"]
}
```

This project uses the current API Token authentication scheme and sends it as
`Authorization: Bearer <API_TOKEN>`. Global API keys and email/key
authentication are not supported. Create a scoped token with `Zone / DNS /
Edit` for the selected zone. WAF synchronization additionally requires
`Account / Account Filter Lists / Edit` for the selected account. The explicit
Zone ID means the application does not need to search for zones first.

All configured domains must belong to `zone_id`. Run another instance with a
separate working directory and service when managing a different zone.

### Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `api_token` | string | required | Cloudflare API token |
| `account_id` | string | required | 32-character Cloudflare Account ID |
| `zone_id` | string | required | 32-character Cloudflare Zone ID used by all DNS records |
| `domains` | string[] | `[]` | Domains updated for IPv4 and IPv6 |
| `ipv4_domains` | string[] | `[]` | Additional IPv4-only domains |
| `ipv6_domains` | string[] | `[]` | Additional IPv6-only domains |
| `ipv4_provider` | string | `cloudflare.trace` | IPv4 detection provider |
| `ipv6_provider` | string | `none` | IPv6 detection provider; `none` disables IPv6 detection and updates |
| `waf_lists` | string[] | `[]` | WAF list names under `account_id` |
| `schedule` | string | `@every 5m` | `@every <duration>` or `@once` |
| `update_on_start` | boolean | `true` | Update immediately at startup |
| `delete_on_stop` | boolean | `false` | Remove managed records and list items on shutdown |
| `delete_on_failure` | boolean | `false` | Delete records after a definitive no-address result |
| `ttl` | integer | `1` | DNS TTL; values below 30 use automatic TTL |
| `proxied` | string | `false` | Expression selecting proxied domains |
| `record_comment` | string/null | `null` | Comment written to managed DNS records |
| `managed_records_comment_regex` | string/null | `null` | Only manage DNS records whose comment matches |
| `waf_list_item_comment` | string/null | `null` | Comment written to WAF list items |
| `managed_waf_list_items_comment_regex` | string/null | `null` | Only manage WAF items whose comment matches |
| `detection_timeout` | string | `5s` | Public IP lookup timeout |
| `update_timeout` | string | `30s` | Cloudflare API timeout |
| `reject_cloudflare_ips` | boolean | `true` | Reject addresses in Cloudflare's published ranges |
| `quiet` | boolean | `false` | Suppress informational output |
| `telegram` | object/null | `null` | Telegram Bot API credentials |

At least one domain field or `waf_lists` entry is required. Durations accept
seconds (`30s`), minutes (`5m`), hours (`2h`), or an integer number of seconds.
For `@once`, `update_on_start` must be `true` and `delete_on_stop` must be
`false`.

### Telegram

Telegram is the only supported notification service. Set the bot token and
target chat ID directly:

```json
{
  "telegram": {
    "bot_token": "123456:bot-token",
    "chat_id": "-1001234567890"
  }
}
```

Notifications are sent when records or WAF lists change, or when an update
fails. The token is stored in `config.json`, so keep the file at mode `0600`.

### IP providers

| Value | Description |
| --- | --- |
| `cloudflare.trace` | Cloudflare `/cdn-cgi/trace` endpoint |
| `cloudflare.doh` | Cloudflare DNS-over-HTTPS whoami lookup |
| `ipify` | ipify public IP API |
| `local` | Address selected from the local routing table |
| `local.iface:<name>` | Address assigned to a specific interface |
| `local.iface.stable:<name>` | Stable IPv6 address on a Linux interface |
| `url:<url>` | Custom HTTP(S) endpoint returning an IP address |
| `literal:<ips>` | Static comma-separated addresses |
| `none` | Disable this address family |

Network lookup failures preserve existing records. Deterministic providers
(`local`, `local.iface:*`, `literal:*`, and `none`) can report a definitive
absence; `delete_on_failure` controls deletion only in that case.

### Proxied expressions

The `proxied` field accepts `true`, `false`, and expressions built from
`is(example.com)`, `sub(example.com)`, `!`, `&&`, `||`, and parentheses.

```json
{
  "proxied": "sub(web.example.com) && !is(private.web.example.com)"
}
```

## Usage

Run from the directory containing `config.json`:

```bash
./ipflare
```

Preview changes without modifying Cloudflare resources:

```bash
./ipflare --dry-run
```

No other command-line flags are supported. Use systemd or OpenRC directly to
start, stop, restart, and inspect the service.

## systemd

The installer creates `/etc/systemd/system/ipflare.service`:

```ini
[Unit]
Description=ipflare
After=network.target

[Service]
Type=simple
WorkingDirectory=/etc/ipflare
ExecStart=/etc/ipflare/ipflare
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Day-to-day service management:

```bash
sudo systemctl start ipflare.service
sudo systemctl stop ipflare.service
sudo systemctl restart ipflare.service
sudo systemctl status ipflare.service
sudo journalctl -u ipflare.service -n 100
```

## OpenRC (Alpine)

On Alpine Linux, the installer creates `/etc/init.d/ipflare`:

```sh
#!/sbin/openrc-run

name="ipflare"
description="Cloudflare dynamic DNS updater"
command="/etc/ipflare/ipflare"
directory="/etc/ipflare"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0

depend() {
    need net
}
```

The service name is `ipflare`. Manage it directly through OpenRC:

```sh
rc-service ipflare start
rc-service ipflare stop
rc-service ipflare restart
rc-service ipflare status
```

## Releases

Push a version tag, for example `v2.2.0`; the workflow applies the tag version to
`Cargo.toml`. It runs the test suite, builds native binaries, and publishes a
GitHub Release. Commit subjects since the previous tag are used as the release
changelog.

## License

GPL-3.0. See [LICENSE](LICENSE).
