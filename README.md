# ipflare

中文 | [English](README_en.md)

一个小型 Rust 客户端，在公网 IP 变化时更新 Cloudflare A/AAAA 记录和
WAF IP 列表。

## 功能

- IPv4、IPv6 独立检测和更新，可分别启用或关闭
- 单个 Cloudflare Zone 下支持多个域名、通配符记录和 IDN 域名
- 同步 Cloudflare WAF IP 列表
- 可选开启 Cloudflare 代理
- 通过注释标记并筛选受管的 DNS 记录和 WAF 列表项
- 可选 Telegram 通知
- 支持定时运行和单次运行
- 支持预演模式和退出时清理
- 拒绝将 Cloudflare Anycast 地址写入 DNS

## 安装

### Linux 一键安装

脚本通用于 Linux x86_64 和 aarch64，使用 POSIX `sh`，支持
`curl` 或 `wget`，并自动识别 systemd 和 OpenRC。程序与配置会安装到：

```text
/etc/ipflare/ipflare
/etc/ipflare/config.json
```

使用 `curl`：

```sh
curl -fsSL https://raw.githubusercontent.com/imengying/IPFlare/main/install.sh | sudo sh
```

没有 `curl` 时使用 `wget`：

```sh
wget -qO- https://raw.githubusercontent.com/imengying/IPFlare/main/install.sh | sudo sh
```

已以 root 身份运行时省略 `sudo`。

必要配置只会询问：

- Cloudflare API Token
- Account ID
- Zone ID
- 需要更新的完整域名
- 是否启用 IPv4 和 IPv6

IPv4 默认启用，IPv6 默认关闭。关闭某个地址族后，也会同时停止对应的
公网 IP 检测和 DNS 更新。

代理、更新间隔、WAF 和 Telegram 收在“其他选项”中，可以直接跳过。
跳过时使用以下默认值：关闭代理、每 5 分钟更新、不配置 WAF、不启用
Telegram。

重新运行脚本会打开更新、重新配置和卸载菜单。更新保留配置；
卸载时只有明确确认才会删除 `config.json`。脚本不安装额外的管理命令。

### Release 文件

每个 Release 压缩包只包含程序本体：

- Linux x86_64 和 aarch64（静态 musl 程序，支持 Alpine）
- macOS Apple Silicon
- Windows x86_64

从源码构建：

```bash
cargo build --release --locked
```

## 配置

程序只读取当前工作目录中的 `config.json`，不支持环境变量和旧版配置格式，
遇到未知字段会直接报错。可以从仓库示例开始：

```bash
cp config-example.json config.json
```

最小配置：

```json
{
  "api_token": "your-cloudflare-api-token",
  "account_id": "11111111111111111111111111111111",
  "zone_id": "22222222222222222222222222222222",
  "domains": ["home.example.com"]
}
```

程序使用 Cloudflare API Token 鉴权，通过
`Authorization: Bearer <API_TOKEN>` 发送令牌。不支持 Global API Key 或
邮箱/API Key 鉴权。Token 至少需要所选 Zone 的 `Zone / DNS / Edit` 权限；
同步 WAF 时还需要所选 Account 的 `Account / Account Filter Lists / Edit`
权限。

所有域名必须属于 `zone_id` 指定的同一个 Zone。管理其他 Zone 时，应使用
独立工作目录和独立 systemd 服务运行另一个实例。

### 配置字段

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `api_token` | string | 必填 | Cloudflare API Token |
| `account_id` | string | 必填 | 32 位 Cloudflare Account ID |
| `zone_id` | string | 必填 | 32 位 Cloudflare Zone ID，所有 DNS 记录共用 |
| `domains` | string[] | `[]` | IPv4、IPv6 共用域名 |
| `ipv4_domains` | string[] | `[]` | 额外的 IPv4 专用域名 |
| `ipv6_domains` | string[] | `[]` | 额外的 IPv6 专用域名 |
| `ipv4_provider` | string | `cloudflare.trace` | IPv4 检测方式 |
| `ipv6_provider` | string | `none` | IPv6 检测方式；`none` 会同时关闭检测和更新 |
| `waf_lists` | string[] | `[]` | `account_id` 下的 WAF 列表名称 |
| `schedule` | string | `@every 5m` | `@every <时长>` 或 `@once` |
| `update_on_start` | boolean | `true` | 启动后立即更新 |
| `delete_on_stop` | boolean | `false` | 停止时删除受管记录和列表项 |
| `delete_on_failure` | boolean | `false` | 明确检测到无地址时删除记录 |
| `ttl` | integer | `1` | DNS TTL；小于 30 时使用自动 TTL |
| `proxied` | boolean | `false` | 是否开启 Cloudflare 代理 |
| `record_comment` | string/null | `null` | 写入受管 DNS 记录的注释 |
| `managed_records_comment_regex` | string/null | `null` | 只管理注释匹配的 DNS 记录 |
| `waf_list_item_comment` | string/null | `null` | 写入 WAF 列表项的注释 |
| `managed_waf_list_items_comment_regex` | string/null | `null` | 只管理注释匹配的 WAF 列表项 |
| `detection_timeout` | string | `10s` | 公网 IP 检测超时 |
| `update_timeout` | string | `30s` | Cloudflare API 请求超时 |
| `reject_cloudflare_ips` | boolean | `true` | 拒绝 Cloudflare 官方网段中的地址 |
| `quiet` | boolean | `false` | 隐藏普通信息 |
| `name` | string/null | `null` | 实例名称，作为通知首行的前缀 |
| `telegram` | object/null | `null` | Telegram Bot API 配置 |

至少需要配置一个域名字段或一个 `waf_lists` 条目。时长支持秒（`30s`）、
分钟（`5m`）、小时（`2h`）或表示秒数的整数。使用 `@once` 时，
`update_on_start` 必须为 `true`，`delete_on_stop` 必须为 `false`。

### Telegram

Telegram 是唯一支持的通知方式：

```json
{
  "telegram": {
    "bot_token": "123456:bot-token",
    "chat_id": "-1001234567890"
  }
}
```

只在 DNS 记录或 WAF 列表内容发生变化时发送通知，例如 IP 变动后的
`已更新 home.example.com: 1.2.3.4 -> 5.6.7.8`。首行带实例名摘要，配置
`name` 后形如 `【名称】ipflare 更新成功`。检测失败、更新失败等运行问题
只写入日志，不发送通知，请通过 journalctl 或服务日志排查。`--dry-run`
只输出到控制台，不发送通知。Token 直接保存在 `config.json` 中，请保持
文件权限为 `0600`。

### IP 检测方式

| 值 | 说明 |
| --- | --- |
| `cloudflare.trace` | Cloudflare `/cdn-cgi/trace` 接口 |
| `cloudflare.doh` | Cloudflare DNS-over-HTTPS whoami 查询 |
| `ipify` | ipify 公网 IP 接口 |
| `local` | 从本地路由表选择地址 |
| `local.iface:<name>` | 指定网卡上的地址 |
| `local.iface.stable:<name>` | Linux 指定网卡上的稳定 IPv6 地址 |
| `url:<url>` | 返回 IP 地址的自定义 HTTP(S) 接口 |
| `literal:<ips>` | 逗号分隔的静态地址 |
| `none` | 关闭对应地址族 |

网络检测失败时会保留现有记录。确定性检测方式（`local`、
`local.iface:*`、`literal:*` 和 `none`）可以明确报告无地址；只有这种情况
才由 `delete_on_failure` 决定是否删除记录。

## 使用

在包含 `config.json` 的目录运行：

```bash
./ipflare
```

只预览变更，不修改 Cloudflare 资源：

```bash
./ipflare --dry-run
```

命令行仅支持 `--dry-run` 和 `--version`（打印版本号后退出）。服务的启动、
停止和状态查看直接使用 systemd 或 OpenRC。

## systemd

安装脚本创建 `/etc/systemd/system/ipflare.service`：

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

日常管理：

```bash
sudo systemctl start ipflare.service
sudo systemctl stop ipflare.service
sudo systemctl restart ipflare.service
sudo systemctl status ipflare.service
sudo journalctl -u ipflare.service -n 100
```

## OpenRC（Alpine）

在 Alpine Linux 上，安装脚本会创建 `/etc/init.d/ipflare`：

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

服务名为 `ipflare`，日常管理直接使用 OpenRC：

```sh
rc-service ipflare start
rc-service ipflare stop
rc-service ipflare restart
rc-service ipflare status
```

## 发布

推送版本标签（例如 `v2.2.0`）会触发发布工作流：把标签版本写回
`Cargo.toml`，运行测试，构建各平台二进制并发布 GitHub Release。
Release 说明取自上一个标签以来的提交标题。

## 许可证

GPL-3.0，参见 [LICENSE](LICENSE)。
