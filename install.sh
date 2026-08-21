#!/bin/sh
set -eu

readonly repository="imengying/IPFlare"
readonly config_dir="/etc/ipflare"
readonly binary_path="${config_dir}/ipflare"
readonly config_path="${config_dir}/config.json"
readonly systemd_service_name="ipflare.service"
readonly systemd_service_path="/etc/systemd/system/${systemd_service_name}"
readonly openrc_service_name="ipflare"
readonly openrc_service_path="/etc/init.d/${openrc_service_name}"

temp_dir=""
tty_open=false
tty_echo_disabled=false
init_system=""
service_path=""
downloader=""

cleanup() {
    if [ "${tty_echo_disabled}" = true ]; then
        stty echo <&3 2>/dev/null || true
    fi
    if [ -n "${temp_dir}" ] && [ -d "${temp_dir}" ]; then
        rm -rf "${temp_dir}"
    fi
}
trap cleanup EXIT HUP INT TERM

fail() {
    echo "错误: $*" >&2
    exit 1
}

ensure_temp_dir() {
    if [ -z "${temp_dir}" ]; then
        temp_dir="$(mktemp -d)"
    fi
}

ensure_tty() {
    if [ "${tty_open}" = false ]; then
        [ -r /dev/tty ] && [ -w /dev/tty ] || fail "此操作需要交互终端"
        exec 3<>/dev/tty
        tty_open=true
    fi
}

require_commands() {
    for required_command in "$@"; do
        command -v "${required_command}" >/dev/null 2>&1 \
            || fail "缺少命令: ${required_command}"
    done
}

detect_init() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        init_system="systemd"
        service_path="${systemd_service_path}"
    elif command -v rc-service >/dev/null 2>&1 \
        && command -v rc-update >/dev/null 2>&1; then
        init_system="openrc"
        service_path="${openrc_service_path}"
    else
        fail "只支持 systemd 或 OpenRC 服务管理器"
    fi
}

select_downloader() {
    if command -v curl >/dev/null 2>&1; then
        downloader="curl"
    elif command -v wget >/dev/null 2>&1; then
        downloader="wget"
    else
        fail "缺少下载工具: 请安装 curl 或 wget"
    fi
}

download_file() {
    download_url="$1"
    download_destination="$2"
    case "${downloader}" in
        curl) curl -fL "${download_url}" -o "${download_destination}" ;;
        wget) wget -O "${download_destination}" "${download_url}" ;;
        *) fail "未选择下载工具" ;;
    esac
}

prompt_value() {
    prompt_label="$1"
    while true; do
        printf '%s: ' "${prompt_label}" >&3
        IFS= read -r prompt_result <&3 || fail "无法读取终端输入"
        if [ -n "${prompt_result}" ]; then
            return
        fi
        printf '该项不能为空。\n' >&3
    done
}

prompt_secret() {
    prompt_label="$1"
    while true; do
        printf '%s: ' "${prompt_label}" >&3
        stty -echo <&3
        tty_echo_disabled=true
        if IFS= read -r prompt_result <&3; then
            read_succeeded=true
        else
            read_succeeded=false
        fi
        stty echo <&3
        tty_echo_disabled=false
        printf '\n' >&3
        [ "${read_succeeded}" = true ] || fail "无法读取终端输入"
        if [ -n "${prompt_result}" ]; then
            return
        fi
        printf '该项不能为空。\n' >&3
    done
}

prompt_default() {
    prompt_label="$1"
    prompt_default_value="$2"
    printf '%s [%s]: ' "${prompt_label}" "${prompt_default_value}" >&3
    IFS= read -r prompt_result <&3 || fail "无法读取终端输入"
    prompt_result="${prompt_result:-${prompt_default_value}}"
}

confirm() {
    confirm_label="$1"
    confirm_default="$2"
    confirm_hint="y/N"
    [ "${confirm_default}" = yes ] && confirm_hint="Y/n"
    while true; do
        printf '%s [%s]: ' "${confirm_label}" "${confirm_hint}" >&3
        IFS= read -r confirm_answer <&3 || fail "无法读取终端输入"
        confirm_answer="$(printf '%s' "${confirm_answer}" | tr '[:upper:]' '[:lower:]')"
        if [ -z "${confirm_answer}" ]; then
            [ "${confirm_default}" = yes ]
            return
        fi
        case "${confirm_answer}" in
            y | yes) return 0 ;;
            n | no) return 1 ;;
            *) printf '请输入 y 或 n。\n' >&3 ;;
        esac
    done
}

validate_id() {
    [ "${#1}" -eq 32 ] || return 1
    case "$1" in
        *[!0-9A-Fa-f]*) return 1 ;;
        *) return 0 ;;
    esac
}

validate_domain() {
    printf '%s\n' "$1" | awk -F. '
        NF < 2 { exit 1 }
        {
            for (i = 1; i <= NF; i++) {
                label = $i
                if (i == 1 && label == "*") continue
                if (length(label) < 1 || length(label) > 63) exit 1
                if (label !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) exit 1
            }
        }
    '
}

validate_interval() {
    interval_value="$1"
    interval_unit="${interval_value#${interval_value%?}}"
    interval_number="${interval_value%?}"
    case "${interval_unit}" in
        s | m | h) ;;
        *) return 1 ;;
    esac
    case "${interval_number}" in
        '' | 0* | *[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

configure() {
    ensure_tty
    ensure_temp_dir
    printf '\n配置 ipflare\n' >&3

    prompt_secret 'Cloudflare API Token（不是 Global API Key）'
    api_token="${prompt_result}"
    case "${api_token}" in
        *[!A-Za-z0-9_-]*) fail "API Token 包含不支持的字符" ;;
    esac

    while true; do
        prompt_value 'Cloudflare Account ID'
        account_id="${prompt_result}"
        validate_id "${account_id}" && break
        printf 'Account ID 必须是 32 位十六进制字符串。\n' >&3
    done

    while true; do
        prompt_value 'Cloudflare Zone ID'
        zone_id="${prompt_result}"
        validate_id "${zone_id}" && break
        printf 'Zone ID 必须是 32 位十六进制字符串。\n' >&3
    done

    while true; do
        prompt_value '需要更新的完整域名'
        domain="${prompt_result}"
        validate_domain "${domain}" && break
        printf '请输入有效域名，例如 home.example.com。\n' >&3
    done

    ipv4_provider="none"
    ipv6_provider="none"
    while [ "${ipv4_provider}" = none ] && [ "${ipv6_provider}" = none ]; do
        if confirm "启用 IPv4 检测和 A 记录更新" yes; then
            ipv4_provider="cloudflare.trace"
        else
            ipv4_provider="none"
        fi
        if confirm "启用 IPv6 检测和 AAAA 记录更新" no; then
            ipv6_provider="cloudflare.trace"
        else
            ipv6_provider="none"
        fi
        if [ "${ipv4_provider}" = none ] && [ "${ipv6_provider}" = none ]; then
            printf 'IPv4 和 IPv6 至少启用一项。\n' >&3
        fi
    done

    interval="5m"
    proxied="false"
    waf_lists_json="[]"
    telegram_json="null"
    if confirm "配置其他选项（代理、更新间隔、WAF、Telegram）" no; then
        if confirm "启用 Cloudflare 代理" no; then
            proxied="true"
        fi

        while true; do
            prompt_default '更新间隔（s/m/h）' '5m'
            interval="${prompt_result}"
            validate_interval "${interval}" && break
            printf '请输入例如 30s、5m 或 2h。\n' >&3
        done

        printf 'WAF IP 列表名（可留空）: ' >&3
        IFS= read -r waf_list_name <&3 || fail "无法读取终端输入"
        if [ -n "${waf_list_name}" ]; then
            case "${waf_list_name}" in
                *[!a-z0-9_]*) fail "WAF 列表名只能包含小写字母、数字和下划线" ;;
            esac
            waf_lists_json="[\"${waf_list_name}\"]"
        fi

        if confirm "启用 Telegram 通知" no; then
            prompt_secret 'Telegram Bot Token'
            telegram_bot_token="${prompt_result}"
            case "${telegram_bot_token}" in
                *[!A-Za-z0-9:_-]*) fail "Telegram Bot Token 包含不支持的字符" ;;
            esac
            while true; do
                prompt_value 'Telegram Chat ID'
                telegram_chat_id="${prompt_result}"
                case "${telegram_chat_id}" in
                    -[0-9]* | [0-9]*)
                        case "${telegram_chat_id#-}" in
                            '' | *[!0-9]*) ;;
                            *) break ;;
                        esac
                        ;;
                esac
                printf 'Chat ID 必须是整数。\n' >&3
            done
            telegram_json="{\"bot_token\":\"${telegram_bot_token}\",\"chat_id\":\"${telegram_chat_id}\"}"
        fi
    fi

    account_id="$(printf '%s' "${account_id}" | tr '[:upper:]' '[:lower:]')"
    zone_id="$(printf '%s' "${zone_id}" | tr '[:upper:]' '[:lower:]')"
    domain="$(printf '%s' "${domain}" | tr '[:upper:]' '[:lower:]')"
    cat >"${temp_dir}/config.json" <<JSON
{
  "api_token": "${api_token}",
  "account_id": "${account_id}",
  "zone_id": "${zone_id}",
  "domains": ["${domain}"],
  "ipv4_provider": "${ipv4_provider}",
  "ipv6_provider": "${ipv6_provider}",
  "waf_lists": ${waf_lists_json},
  "schedule": "@every ${interval}",
  "proxied": "${proxied}",
  "record_comment": "ipflare",
  "telegram": ${telegram_json}
}
JSON
    install -d -m 0700 "${config_dir}"
    install -m 0600 "${temp_dir}/config.json" "${config_path}"
}

write_service() {
    ensure_temp_dir
    if [ "${init_system}" = systemd ]; then
        cat >"${temp_dir}/ipflare.service" <<'UNIT'
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
UNIT
        install -m 0644 "${temp_dir}/ipflare.service" "${systemd_service_path}"
    else
        cat >"${temp_dir}/ipflare.openrc" <<'OPENRC'
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
OPENRC
        install -m 0755 "${temp_dir}/ipflare.openrc" "${openrc_service_path}"
    fi
}

enable_and_restart_service() {
    if [ "${init_system}" = systemd ]; then
        systemctl daemon-reload
        systemctl enable "${systemd_service_name}"
        systemctl restart "${systemd_service_name}"
    else
        rc-update add "${openrc_service_name}" default >/dev/null
        if rc-service "${openrc_service_name}" status >/dev/null 2>&1; then
            rc-service "${openrc_service_name}" restart
        else
            rc-service "${openrc_service_name}" start
        fi
    fi
}

disable_and_stop_service() {
    if [ "${init_system}" = systemd ]; then
        systemctl disable --now "${systemd_service_name}" >/dev/null 2>&1 || true
    else
        rc-service "${openrc_service_name}" stop >/dev/null 2>&1 || true
        rc-update del "${openrc_service_name}" default >/dev/null 2>&1 || true
    fi
}

reload_service_manager() {
    if [ "${init_system}" = systemd ]; then
        systemctl daemon-reload
    fi
}

resolve_platform() {
    case "$(uname -m)" in
        x86_64 | amd64) platform="linux-x86_64" ;;
        aarch64 | arm64) platform="linux-aarch64" ;;
        *) fail "不支持的架构: $(uname -m)" ;;
    esac
}

validate_tag() {
    printf '%s\n' "$1" | awk '
        /^v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*([.-][0-9A-Za-z.-][0-9A-Za-z.-]*)?$/ { valid = 1 }
        END { exit !valid }
    '
}

resolve_tag() {
    tag="${VERSION:-}"
    if [ -z "${tag}" ]; then
        if [ "${downloader}" = curl ]; then
            release_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
                "https://github.com/${repository}/releases/latest")"
            tag="${release_url##*/}"
        else
            release_json="$(wget -qO- \
                "https://api.github.com/repos/${repository}/releases/latest")"
            tag="$(printf '%s\n' "${release_json}" \
                | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                | head -n 1)"
        fi
    fi
    validate_tag "${tag}" || fail "无效版本标签: ${tag}"
}

install_or_update() {
    require_commands awk chmod head install mktemp rm sed sha256sum tar tr
    select_downloader
    ensure_temp_dir
    resolve_platform
    resolve_tag

    asset="ipflare-${tag}-${platform}.tar.gz"
    release_base="https://github.com/${repository}/releases/download/${tag}"

    echo "正在下载 ${asset}..."
    download_file "${release_base}/${asset}" "${temp_dir}/${asset}"
    download_file "${release_base}/SHA256SUMS" "${temp_dir}/SHA256SUMS"

    expected_checksum="$(awk -v asset="${asset}" '$2 == asset { print $1 }' \
        "${temp_dir}/SHA256SUMS")"
    [ -n "${expected_checksum}" ] || fail "发布文件中没有 ${asset} 的校验值"
    actual_checksum="$(sha256sum "${temp_dir}/${asset}" | awk '{ print $1 }')"
    [ "${actual_checksum}" = "${expected_checksum}" ] || fail "SHA-256 校验失败"

    tar -xzf "${temp_dir}/${asset}" -C "${temp_dir}"
    [ -f "${temp_dir}/ipflare" ] || fail "发布包中没有 ipflare"
    install -d -m 0700 "${config_dir}"
    install -m 0755 "${temp_dir}/ipflare" "${binary_path}"

    if [ ! -f "${config_path}" ]; then
        configure
    else
        chmod 0600 "${config_path}"
    fi

    write_service
    enable_and_restart_service

    echo "ipflare ${tag} 安装或更新完成。"
    echo "服务管理器: ${init_system}"
    if [ "${init_system}" = systemd ]; then
        echo "服务: ${systemd_service_name}"
    else
        echo "服务: ${openrc_service_name}"
    fi
    echo "配置: ${config_path}"
    echo "更新、重配或卸载时，请重新运行一键脚本。"
}

reconfigure() {
    [ -x "${binary_path}" ] || fail "尚未安装 ipflare"
    configure
    write_service
    enable_and_restart_service
    echo "配置已更新，服务已重启。"
}

uninstall_ipflare() {
    ensure_tty
    if ! confirm "确认卸载 ipflare" no; then
        echo "已取消。"
        return
    fi

    disable_and_stop_service
    rm -f "${systemd_service_path}" "${openrc_service_path}" "${binary_path}"
    reload_service_manager

    if [ -f "${config_path}" ]; then
        if confirm "同时删除 ${config_path}" no; then
            rm -f "${config_path}"
            rmdir "${config_dir}" 2>/dev/null || true
            echo "程序、服务和配置已删除。"
        else
            echo "程序和服务已删除，配置保留在 ${config_path}。"
        fi
    else
        echo "程序和服务已删除。"
    fi
}

usage() {
    cat <<'HELP'
用法: install.sh [命令]

命令:
  install     安装或重新安装
  update      更新到最新版本并重启
  configure   重新生成 config.json
  uninstall   卸载程序和服务
  help        显示帮助

不带命令重新运行一键脚本可打开管理菜单。

服务启停请直接使用系统服务管理器:
  systemd: systemctl start|stop|restart|status ipflare.service
  OpenRC:  rc-service ipflare start|stop|restart|status
HELP
}

select_action() {
    ensure_tty
    printf '\nipflare 安装管理\n' >&3
    printf '1) 更新或重新安装\n' >&3
    printf '2) 重新配置\n' >&3
    printf '3) 卸载\n' >&3
    printf '0) 退出\n' >&3
    printf '请选择: ' >&3
    IFS= read -r choice <&3 || fail "无法读取终端输入"
    case "${choice}" in
        1) action="update" ;;
        2) action="configure" ;;
        3) action="uninstall" ;;
        0) action="exit" ;;
        *) fail "无效选项: ${choice}" ;;
    esac
}

[ "$(uname -s)" = Linux ] || fail "安装脚本仅支持 Linux"
case "${1:-}" in
    help | --help | -h)
        usage
        exit 0
        ;;
esac

[ "$(id -u)" -eq 0 ] || fail "请使用 root 运行一键脚本"
[ "$#" -le 1 ] || fail "只接受一个命令；运行 install.sh help 查看帮助"
require_commands awk id install mktemp rm rmdir stty tr uname
detect_init

action="${1:-}"
if [ -z "${action}" ]; then
    if [ -x "${binary_path}" ] || [ -f "${service_path}" ]; then
        select_action
    else
        action="install"
    fi
fi

case "${action}" in
    install | update) install_or_update ;;
    configure) reconfigure ;;
    uninstall) uninstall_ipflare ;;
    exit) ;;
    *)
        usage
        fail "未知命令: ${action}"
        ;;
esac
