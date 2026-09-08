#!/usr/bin/env bash
set -Eeuo pipefail

readonly RELEASE_TAG="v0.1.0-preview.4"
readonly REPOSITORY="pixingzoudaiyuexing/goedge-ip-cert"
readonly SERVICE_USER="${GOEDGE_IP_CERT_SERVICE_USER:-goedge-ip-cert}"
readonly SERVICE_GROUP="${GOEDGE_IP_CERT_SERVICE_GROUP:-goedge-ip-cert}"
readonly DEFAULT_ENDPOINT="http://127.0.0.1:8002"
ROOT_PREFIX="${GOEDGE_IP_CERT_ROOT_PREFIX:-}"

path() { printf '%s%s' "$ROOT_PREFIX" "$1"; }
say() { printf '%s\n' "$*"; }
die() { say "错误: $*" >&2; return 1; }

banner() {
	cat <<'EOF'
=====================================
 GoEdge IPv4 Certificate Manager
=====================================
EOF
}

preparation_prompt() {
	banner
	cat <<'EOF'

首次安装前请准备：

- GoEdge 1.3.9 已正常部署
- 节点 / 集群已经配置好
- 已提前创建好需要申请证书的网站
- 网站“域名”位置填写公网 IPv4
- 已准备 REST Access Key
- 已准备 REST Access Token

脚本会自动完成：

- MySQL 最小权限账号
- goedge-ip-cert 安装
- 配置文件
- ACME / state
- systemd service
- systemd timer
- 自动续期

按 Enter 继续
输入 q 退出
EOF
	local answer
	IFS= read -r answer || true
	[ "$answer" != "q" ] && [ "$answer" != "Q" ]
}

require_root() {
	[ "${GOEDGE_IP_CERT_TEST_MODE:-0}" = "1" ] || [ "$(id -u)" -eq 0 ] || die "请使用 root 运行"
}

detect_os() {
	local file="${GOEDGE_IP_CERT_OS_RELEASE:-$(path /etc/os-release)}"
	[ -r "$file" ] || die "无法读取 /etc/os-release"
	local id version
	id=$(awk -F= '$1=="ID" {gsub(/^"|"$/, "", $2); print $2}' "$file")
	version=$(awk -F= '$1=="VERSION_ID" {gsub(/^"|"$/, "", $2); print $2}' "$file")
	[ "$id" = "debian" ] && [ "$version" = "12" ] || die "仅支持 Debian 12"
	printf 'debian-12\n'
}

detect_arch() {
	local machine="${GOEDGE_IP_CERT_UNAME_M:-$(uname -m)}"
	case "$machine" in
		x86_64|amd64) printf 'amd64\n' ;;
		aarch64|arm64) printf 'arm64\n' ;;
		*) die "不支持的架构: $machine" ;;
	esac
}

ensure_dependencies() {
	local missing=() command_name
	for command_name in curl sha256sum jq openssl mysql flock runuser tar systemctl; do
		command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
	done
	if [ "${#missing[@]}" -gt 0 ]; then
		[ "${GOEDGE_IP_CERT_TEST_MODE:-0}" = "1" ] && die "缺少命令: ${missing[*]}"
		DEBIAN_FRONTEND=noninteractive apt-get update -qq
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates jq openssl default-mysql-client util-linux systemd tar
	fi
}

prepare_install_state() {
	local candidate
	RESUME_INSTALL=0
	if [ -f "$(path /etc/goedge-ip-cert/.installing)" ]; then
		RESUME_INSTALL=1
		return 0
	fi
	for candidate in /usr/local/bin/goedge-ip-cert /usr/local/sbin/goedge-ip-cert-manager /etc/goedge-ip-cert /var/lib/goedge-ip-cert; do
		if [ -e "$(path "$candidate")" ]; then
			die "EXISTING_INSTALLATION_DETECTED: $candidate 已存在；拒绝覆盖已有配置或 state"
			return 1
		fi
	done
}

detect_systemd() {
	command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd"
	[ "${GOEDGE_IP_CERT_TEST_MODE:-0}" = "1" ] || [ -d /run/systemd/system ] || die "systemd 不是当前 init system"
}

find_goedge_root() {
	local candidate
	if [ -n "${GOEDGE_ROOT:-}" ]; then
		candidate="$GOEDGE_ROOT"
		[ -x "$candidate/edge-admin/edge-api/bin/edge-api" ] || die "GOEDGE_ROOT 中未找到 EdgeAPI"
		printf '%s\n' "$candidate"
		return
	fi
	for candidate in /www/wwwroot/goedge /opt/goedge /usr/local/goedge; do
		candidate=$(path "$candidate")
		if [ -x "$candidate/edge-admin/edge-api/bin/edge-api" ]; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	die "未检测到 GoEdge / EdgeAPI"
}

find_goedge_db_config() {
	local root="$1" candidate
	if [ -n "${GOEDGE_DB_CONFIG:-}" ]; then
		[ -r "$GOEDGE_DB_CONFIG" ] || die "GOEDGE_DB_CONFIG 不可读"
		printf '%s\n' "$GOEDGE_DB_CONFIG"
		return
	fi
	for candidate in "$root/edge-admin/edge-api/configs/db.yaml" "$root/edge-admin/edge-api/configs/.db.yaml"; do
		if [ -r "$candidate" ]; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	die "AUTO_DB_INITIALIZATION_FAILED: 未找到 GoEdge EdgeAPI db.yaml"
}

read_secret() {
	local prompt="$1" value
	printf '%s' "$prompt" >&2
	IFS= read -r -s value
	printf '\n' >&2
	[ -n "$value" ] || die "输入不能为空"
	printf '%s' "$value"
}

release_base() {
	printf '%s\n' "${GOEDGE_IP_CERT_RELEASE_BASE:-https://github.com/$REPOSITORY/releases/download/${DOWNLOAD_TAG:-$RELEASE_TAG}}"
}

download_release() {
	local asset="$1" destination="$2" base sums expected actual
	base=$(release_base)
	sums=$(mktemp)
	curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 3 "$base/SHA256SUMS" -o "$sums"
	expected=$(awk -v name="$asset" '$2==name || $2=="*"name {print $1}' "$sums")
	[ "${#expected}" -eq 64 ] || die "SHA256SUMS 中缺少 $asset"
	curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 3 "$base/$asset" -o "$destination"
	actual=$(sha256sum "$destination" | awk '{print $1}')
	if [ "$actual" != "$expected" ]; then
		rm -f "$sums" "$destination"
		die "SHA256 校验失败: $asset"
	fi
	rm -f "$sums"
}

install_private_value() {
	local value="$1" destination="$2" temporary
	temporary=$(mktemp)
	printf '%s\n' "$value" >"$temporary"
	install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 "$temporary" "$destination"
	rm -f "$temporary"
}

write_manager_config() {
	local destination="$1" db_config="$2" database_name="$3"
	cat >"$destination" <<EOF
GOEDGE_ENDPOINT=$DEFAULT_ENDPOINT
GOEDGE_DB_CONFIG=$db_config
RELEASE_TAG=$RELEASE_TAG
DATABASE_NAME=$database_name
EOF
	chmod 0640 "$destination"
}

install_systemd_units() {
	local service timer
	service=$(path /etc/systemd/system/goedge-ip-cert.service)
	timer=$(path /etc/systemd/system/goedge-ip-cert.timer)
	cat >"$service" <<'EOF'
[Unit]
Description=GoEdge IPv4 certificate renewal check
Wants=network-online.target
After=network-online.target
ConditionFileIsExecutable=/usr/local/bin/goedge-ip-cert
ConditionFileIsExecutable=/usr/local/sbin/goedge-ip-cert-manager

[Service]
Type=oneshot
User=goedge-ip-cert
Group=goedge-ip-cert
ExecStart=/usr/local/sbin/goedge-ip-cert-manager run-all
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
ReadOnlyPaths=/etc/goedge-ip-cert
ReadWritePaths=/var/lib/goedge-ip-cert
UMask=0077
TimeoutStartSec=10min
StandardOutput=journal
StandardError=journal
EOF
	cat >"$timer" <<'EOF'
[Unit]
Description=Hourly GoEdge IPv4 certificate renewal check

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=5m
AccuracySec=1m
Unit=goedge-ip-cert.service

[Install]
WantedBy=timers.target
EOF
	chmod 0644 "$service" "$timer"
}

install_initialize() {
	require_root
	preparation_prompt || { say "已退出"; return 0; }
	detect_os >/dev/null
	local arch goedge_root db_config tmp binary access_key access_token
	arch=$(detect_arch)
	ensure_dependencies
	detect_systemd
	goedge_root=$(find_goedge_root)
	db_config=$(find_goedge_db_config "$goedge_root")
	prepare_install_state
	tmp=$(mktemp -d)
	binary="$tmp/goedge-ip-cert"
	download_release "goedge-ip-cert-linux-$arch" "$binary"
	chmod 0755 "$binary"
	download_release "install.sh" "$tmp/install.sh"
	chmod 0755 "$tmp/install.sh"
	[ "$("$binary" version)" = "$RELEASE_TAG" ] || die "下载的 binary 版本不一致"
	[ "$(GOEDGE_IP_CERT_SOURCE_ONLY=0 "$tmp/install.sh" --version)" = "$RELEASE_TAG" ] || die "下载的 manager 版本不一致"
	getent group "$SERVICE_GROUP" >/dev/null 2>&1 || groupadd --system "$SERVICE_GROUP"
	id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --gid "$SERVICE_GROUP" --home-dir /var/lib/goedge-ip-cert --shell /usr/sbin/nologin "$SERVICE_USER"
	install -d -o root -g "$SERVICE_GROUP" -m 0750 "$(path /etc/goedge-ip-cert)" "$(path /etc/goedge-ip-cert/credentials)" "$(path /etc/goedge-ip-cert/targets.d)"
	if [ "$RESUME_INSTALL" -eq 0 ]; then
		install -o root -g root -m 0600 /dev/null "$(path /etc/goedge-ip-cert/.installing)"
	fi
	install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$(path /var/lib/goedge-ip-cert)" "$(path /var/lib/goedge-ip-cert/targets)"
	install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 /dev/null "$(path /var/lib/goedge-ip-cert/manager.lock)"
	if [ ! -f "$(path /etc/goedge-ip-cert/credentials/goedge-access-key-id)" ] ||
		[ ! -f "$(path /etc/goedge-ip-cert/credentials/goedge-access-key)" ]; then
		access_key=$(read_secret "GoEdge REST Access Key: ")
		access_token=$(read_secret "GoEdge REST Access Token: ")
		install_private_value "$access_key" "$(path /etc/goedge-ip-cert/credentials/goedge-access-key-id)"
		install_private_value "$access_token" "$(path /etc/goedge-ip-cert/credentials/goedge-access-key)"
	fi
	"$binary" discover-websites --endpoint "$DEFAULT_ENDPOINT" \
		--access-key-id-file "$(path /etc/goedge-ip-cert/credentials/goedge-access-key-id)" \
		--access-key-file "$(path /etc/goedge-ip-cert/credentials/goedge-access-key)" >/dev/null
	"$binary" bootstrap-db --goedge-db-config "$db_config" --output "$(path /etc/goedge-ip-cert/credentials/mysql-dsn)" \
		--database-output "$(path /etc/goedge-ip-cert/database-name)" || die "AUTO_DB_INITIALIZATION_FAILED"
	chown "$SERVICE_USER:$SERVICE_GROUP" "$(path /etc/goedge-ip-cert/credentials/mysql-dsn)"
	install -o root -g root -m 0755 "$binary" "$(path /usr/local/bin/goedge-ip-cert)"
	install -o root -g root -m 0755 "$tmp/install.sh" "$(path /usr/local/sbin/goedge-ip-cert-manager)"
	local database_name
	database_name=$(tr -d '\r\n' <"$(path /etc/goedge-ip-cert/database-name)")
	[[ "$database_name" =~ ^[A-Za-z0-9_]+$ ]] || die "数据库名验证失败"
	write_manager_config "$(path /etc/goedge-ip-cert/manager.conf)" "$db_config" "$database_name"
	printf '%s\n' "$RELEASE_TAG" >"$(path /etc/goedge-ip-cert/installed-version)"
	chmod 0644 "$(path /etc/goedge-ip-cert/installed-version)"
	install_systemd_units
	if [ -z "$ROOT_PREFIX" ]; then
		systemctl daemon-reload
		systemctl enable --now goedge-ip-cert.timer
	fi
	rm -f "$(path /etc/goedge-ip-cert/.installing)"
	rm -rf "$tmp"
	unset access_key access_token
	say "安装完成；初始安装未创建 ACME order，也未申请证书。"
}

load_manager_config() {
	local file
	file=$(path /etc/goedge-ip-cert/manager.conf)
	[ -r "$file" ] || die "尚未完成安装 / 初始化"
	GOEDGE_ENDPOINT="$DEFAULT_ENDPOINT"
	DATABASE_NAME=$(awk -F= '$1=="DATABASE_NAME" {print substr($0, index($0, "=")+1)}' "$file")
	[[ "$DATABASE_NAME" =~ ^[A-Za-z0-9_]+$ ]] || die "manager.conf 数据库名无效"
}

core() {
	if [ "${GOEDGE_IP_CERT_TEST_MODE:-0}" != "1" ] && [ "$(id -u)" -eq 0 ]; then
		runuser -u "$SERVICE_USER" -- "$(path /usr/local/bin/goedge-ip-cert)" "$@"
	else
		"$(path /usr/local/bin/goedge-ip-cert)" "$@"
	fi
}

target_config_path() { printf '%s/%s.yaml' "$(path /etc/goedge-ip-cert/targets.d)" "$1"; }
target_state_dir() { printf '%s/%s' "$(path /var/lib/goedge-ip-cert/targets)" "$1"; }

acquire_global_lock() {
	local lock_dir
	lock_dir=$(path /var/lib/goedge-ip-cert)
	[ -d "$lock_dir" ] || die "Cert Manager state 目录不存在"
	exec 8>"$lock_dir/manager.lock"
	flock -n 8 || die "已有 Cert Manager 任务运行中"
}

release_global_lock() {
	flock -u 8 || true
	exec 8>&-
}

write_target_config() {
	local ipv4="$1" destination state_dir temporary
	destination="${2:-$(target_config_path "$ipv4")}"
	state_dir=$(target_state_dir "$ipv4")
	[ ! -e "$destination" ] || return 0
	if [ "${GOEDGE_IP_CERT_TEST_MODE:-0}" = "1" ]; then
		mkdir -p "$state_dir/account" "$state_dir/rollback"
		chmod 0700 "$state_dir" "$state_dir/account" "$state_dir/rollback"
	else
		install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$state_dir" "$state_dir/account" "$state_dir/rollback"
	fi
	temporary=$(mktemp)
	cat >"$temporary" <<EOF
version: 1
target:
  ipv4: $ipv4
goedge:
  endpoint: $GOEDGE_ENDPOINT
  identity_type: admin
  access_key_id:
    file: /etc/goedge-ip-cert/credentials/goedge-access-key-id
  access_key:
    file: /etc/goedge-ip-cert/credentials/goedge-access-key
  request_timeout: 15s
database:
  name: $DATABASE_NAME
  dsn:
    file: /etc/goedge-ip-cert/credentials/mysql-dsn
acme:
  directory_url: https://acme-v02.api.letsencrypt.org/directory
  email: goedge-ip-cert@users.noreply.github.com
  account_dir: /var/lib/goedge-ip-cert/targets/$ipv4/account
state:
  path: /var/lib/goedge-ip-cert/targets/$ipv4/state.db
schedule:
  renew_before: 72h
  retry_min: 15m
  retry_max: 6h
  jitter_max: 10m
EOF
	if [ "${GOEDGE_IP_CERT_TEST_MODE:-0}" = "1" ]; then
		install -m 0640 "$temporary" "$destination"
	else
		install -o root -g "$SERVICE_GROUP" -m 0640 "$temporary" "$destination"
	fi
	rm -f "$temporary"
}

discover_websites() {
	load_manager_config
	core discover-websites --endpoint "$GOEDGE_ENDPOINT" \
		--access-key-id-file /etc/goedge-ip-cert/credentials/goedge-access-key-id \
		--access-key-file /etc/goedge-ip-cert/credentials/goedge-access-key
}

apply_new_website() {
	require_root
	local data count index row ipv4 name cluster config final_config dry answer status cert_id policy_id is_new
	acquire_global_lock
	load_manager_config
	data=$(discover_websites)
	count=$(jq 'length' <<<"$data")
	[ "$count" -gt 0 ] || die "没有发现符合条件的单公网 IPv4 网站"
	say "请选择需要申请 IPv4 证书的网站："
	for ((index=0; index<count; index++)); do
		row=$(jq -c ".[$index]" <<<"$data")
		ipv4=$(jq -r '.ipv4' <<<"$row")
		name=$(jq -r '.name' <<<"$row")
		cluster=$(jq -r '.cluster' <<<"$row")
		status="未申请"
		[ -f "$(target_config_path "$ipv4")" ] && status="已管理"
		printf '\n[%d] %s\n    IPv4: %s\n    集群: %s\n    状态: %s\n' "$((index+1))" "$name" "$ipv4" "$cluster" "$status"
	done
	printf '\n请选择编号: '
	IFS= read -r index
	[[ "$index" =~ ^[0-9]+$ ]] && [ "$index" -ge 1 ] && [ "$index" -le "$count" ] || die "无效编号"
	row=$(jq -c ".[$((index-1))]" <<<"$data")
	ipv4=$(jq -r '.ipv4' <<<"$row")
	name=$(jq -r '.name' <<<"$row")
	cluster=$(jq -r '.cluster' <<<"$row")
	final_config=$(target_config_path "$ipv4")
	config="$final_config"
	is_new=0
	if [ ! -f "$final_config" ]; then
		config="$(path /etc/goedge-ip-cert/targets.d)/.pending-$ipv4"
		is_new=1
	fi
	write_target_config "$ipv4" "$config"
	dry=$(mktemp)
	core run-once --config "$config" >"$dry"
	[ "$(jq -r '.IPv4' "$dry")" = "$ipv4" ] || die "dry-run 目标不一致"
	[ "$(jq -r '.ServerID' "$dry")" = "$(jq -r '.serverId' <<<"$row")" ] || die "dry-run Server 不一致"
	[ "$(jq -r '.PolicyID' "$dry")" = "$(jq -r '.policyId' <<<"$row")" ] || die "dry-run Policy 不一致"
	printf '\n网站: %s\nIPv4: %s\n集群: %s\nDry-run: PASS\n确认向 Let\047s Encrypt Production 申请 shortlived 证书？[y/N] ' "$name" "$ipv4" "$cluster"
	IFS= read -r answer
	[ "$answer" = "y" ] || [ "$answer" = "Y" ] || { [ "$is_new" -eq 0 ] || rm -f "$config"; rm -f "$dry"; release_global_lock; say "已取消，未创建 ACME order。"; return 0; }
	if [ "$is_new" -eq 1 ]; then
		mv "$config" "$final_config"
		config="$final_config"
	fi
	if ! core run-once --config "$config" --apply; then
		status=$(core target-status --config "$config")
		cert_id=$(jq -r '.certId' <<<"$status")
		policy_id=$(jq -r '.policyId' <<<"$status")
		[ "$cert_id" -gt 0 ] || die "证书申请失败；已保留 persistent backoff，请查看日志"
		say "证书申请成功"
		printf '网站: %s\nIPv4: %s\nGoEdge Cert ID: %s\n\n请进入 GoEdge 对应网站的 HTTPS 页面，手工把 Cert ID %s 绑定到 SSL Policy %s。\n' "$name" "$ipv4" "$cert_id" "$cert_id" "$policy_id"
		printf '绑定完成后按 Enter 检测，输入 q 稍后处理: '
		IFS= read -r answer || true
		if [ "$answer" = "q" ] || [ "$answer" = "Q" ]; then
			rm -f "$dry"
			release_global_lock
			return 0
		fi
		core run-once --config "$config" --apply
	fi
	rm -f "$dry"
	release_global_lock
}

status_label() {
	case "$1" in
		ACTIVE) printf '正常' ;;
		CERT_CREATED) printf '待绑定' ;;
		RENEWING) printf '续期中' ;;
		ERROR) printf '续期失败' ;;
		*) printf '%s' "$1" ;;
	esac
}

show_status() {
	local config json ipv4 label bound auto node https cert remaining issuer environment ip_san not_after renew_before next_renewal last_success last_result trust now state timer_ready
	now=$(date +%s)
	timer_ready=0
	if [ -n "$ROOT_PREFIX" ] || { systemctl is-enabled --quiet goedge-ip-cert.timer && systemctl is-active --quiet goedge-ip-cert.timer; }; then
		timer_ready=1
	fi
	shopt -s nullglob
	local configs=("$(path /etc/goedge-ip-cert/targets.d)"/*.yaml)
	[ "${#configs[@]}" -gt 0 ] || { say "尚无受管 IPv4。"; return 0; }
	for config in "${configs[@]}"; do
		json=$(core target-status --config "$config") || { say "$(basename "$config"): 状态读取失败"; continue; }
		ipv4=$(jq -r '.ipv4' <<<"$json")
		state=$(jq -r '.state' <<<"$json")
		label=$(status_label "$state")
		bound=$(jq -r 'if .bound then "已绑定" else "待绑定" end' <<<"$json")
		if [ "$timer_ready" -eq 1 ] && [ "$(jq -r '.autoRenew' <<<"$json")" = "true" ]; then
			auto="开启"
		else
			auto="等待绑定 / Timer未启用"
		fi
		node=$(jq -r 'if .nodeOnline then "正常" else "Node离线" end' <<<"$json")
		https=$(jq -r '.httpsStatus' <<<"$json")
		cert=$(jq -r '.certId' <<<"$json")
		remaining=$(jq -r '.remaining // ""' <<<"$json")
		issuer=$(jq -r '.issuer // ""' <<<"$json")
		environment=$(jq -r '.environment' <<<"$json")
		ip_san=$(jq -r 'if .ipSan then "PASS" else "FAIL" end' <<<"$json")
		not_after=$(jq -r '.notAfter' <<<"$json")
		renew_before=$(jq -r '.renewBefore' <<<"$json")
		next_renewal=$(jq -r '.nextRenewalAt' <<<"$json")
		last_success=$(jq -r '.lastSuccessAt' <<<"$json")
		last_result=$(jq -r 'if .lastError == "" then "正常" else .lastError end' <<<"$json")
		trust=$(jq -r 'if .systemTrust then "PASS" else "FAIL / 未验证" end' <<<"$json")
		if [ "$not_after" -gt 0 ] && [ "$not_after" -le "$now" ]; then
			label="证书已过期"
		elif [ "$not_after" -gt 0 ] && [ "$((not_after-now))" -le 86400 ]; then
			label="证书即将过期"
		elif [ "$state" = "ACTIVE" ] && [ "$next_renewal" -gt 0 ] && [ "$next_renewal" -le "$now" ]; then
			label="即将续期"
		fi
		[ "$https" != "HTTPS异常" ] || label="HTTPS异常"
		[ "$node" != "Node离线" ] || label="Node离线"
		printf '\n%s\n  状态：%s\n  绑定状态：%s\n  网站：%s\n  集群：%s\n  GoEdge Cert ID：%s\n  证书状态：%s\n  签发机构：%s\n  CA 环境：%s\n  IP SAN：%s\n  到期时间：%s\n  剩余有效期：%s\n  自动续期：%s\n  RenewBefore：%s\n  预计进入续期窗口：%s\n  最近续期时间：%s\n  最近续期结果：%s\n  Node 状态：%s\n  HTTPS 状态：%s\n  系统信任状态：%s\n' \
			"$ipv4" "$label" "$bound" "$(jq -r '.website' <<<"$json")" "$(jq -r '.cluster' <<<"$json")" "$cert" "$label" \
			"$issuer" "$environment" "$ip_san" "$not_after" "$remaining" "$auto" "$renew_before" "$next_renewal" "$last_success" "$last_result" "$node" "$https" "$trust"
	done
}

run_all() {
	load_manager_config
	local lock_file config result=0
	lock_file=$(path /var/lib/goedge-ip-cert/manager.lock)
	exec 9>"$lock_file"
	flock -n 9 || die "已有续期任务运行中"
	shopt -s nullglob
	local configs=("$(path /etc/goedge-ip-cert/targets.d)"/*.yaml)
	for config in "${configs[@]}"; do
		core run-once --config "$config" --apply || result=1
	done
	return "$result"
}

show_logs() {
	printf '1. 查看最近日志\n2. 实时查看\n请选择: '
	local answer
	IFS= read -r answer
	case "$answer" in
		1) journalctl -u goedge-ip-cert.service -n 200 --no-pager ;;
		2) journalctl -u goedge-ip-cert.service -f ;;
		*) die "无效选择" ;;
	esac
}

update_program() {
	require_root
	local arch tmp binary old_binary old_manager latest
	acquire_global_lock
	arch=$(detect_arch)
	latest=$(curl -fsSL --proto '=https' --tlsv1.2 --max-redirs 0 \
		"https://api.github.com/repos/$REPOSITORY/releases?per_page=20" | jq -r '[.[] | select(.draft == false)][0].tag_name')
	[[ "$latest" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-preview\.[0-9]+$ ]] || die "无法确认 GitHub Preview Release"
	DOWNLOAD_TAG="$latest"
	tmp=$(mktemp -d)
	download_release "goedge-ip-cert-linux-$arch" "$tmp/goedge-ip-cert"
	download_release "install.sh" "$tmp/install.sh"
	chmod 0755 "$tmp/goedge-ip-cert" "$tmp/install.sh"
	[ "$("$tmp/goedge-ip-cert" version)" = "$latest" ] || die "新 binary 版本验证失败"
	[ "$(GOEDGE_IP_CERT_SOURCE_ONLY=0 "$tmp/install.sh" --version)" = "$latest" ] || die "新 manager 版本验证失败"
	old_binary="$(path /usr/local/bin/goedge-ip-cert).previous"
	old_manager="$(path /usr/local/sbin/goedge-ip-cert-manager).previous"
	cp -p "$(path /usr/local/bin/goedge-ip-cert)" "$old_binary"
	cp -p "$(path /usr/local/sbin/goedge-ip-cert-manager)" "$old_manager"
	if ! install -o root -g root -m 0755 "$tmp/goedge-ip-cert" "$(path /usr/local/bin/goedge-ip-cert)" ||
		! install -o root -g root -m 0755 "$tmp/install.sh" "$(path /usr/local/sbin/goedge-ip-cert-manager)"; then
		mv -f "$old_binary" "$(path /usr/local/bin/goedge-ip-cert)"
		mv -f "$old_manager" "$(path /usr/local/sbin/goedge-ip-cert-manager)"
		die "更新失败，已恢复旧 binary 和 manager"
	fi
	rm -f "$old_binary" "$old_manager"
	rm -rf "$tmp"
	release_global_lock
	say "已更新到 $latest；配置、凭据、ACME account、state 和 targets 均已保留。"
}

backup_restore_menu() {
	printf '1. 创建备份\n2. 恢复备份\n请选择: '
	local answer
	IFS= read -r answer
	case "$answer" in
		1) create_backup ;;
		2) restore_backup ;;
		*) die "无效选择" ;;
	esac
}

create_backup() {
	require_root
	local dir file
	acquire_global_lock
	dir=$(path /var/backups/goedge-ip-cert)
	if [ "${GOEDGE_IP_CERT_TEST_MODE:-0}" = "1" ]; then
		mkdir -p "$dir"
		chmod 0700 "$dir"
	else
		install -d -o root -g root -m 0700 "$dir"
	fi
	file="$dir/goedge-ip-cert-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
	say "警告：备份包含 REST、数据库和 ACME 敏感凭据，请加密保管。"
	tar --exclude='var/lib/goedge-ip-cert/targets/*/rollback' --exclude='*.log' -C "${ROOT_PREFIX:-/}" -czf "$file" etc/goedge-ip-cert var/lib/goedge-ip-cert
	chmod 0600 "$file"
	release_global_lock
	say "备份已创建: $file"
}

restore_backup() {
	require_root
	local file entry staging config
	acquire_global_lock
	printf '请输入备份文件绝对路径: '
	IFS= read -r file
	[ -f "$file" ] || die "备份文件不存在"
	while IFS= read -r entry; do
		[[ "$entry" != /* && "$entry" != *".."* && ( "$entry" == etc/goedge-ip-cert* || "$entry" == var/lib/goedge-ip-cert* ) && "$entry" != *"/rollback"* ]] || die "备份包含不安全路径"
	done < <(tar -tzf "$file")
	while IFS= read -r entry; do
		case "${entry:0:1}" in
			-|d) ;;
			*) die "备份包含不允许的特殊文件" ;;
		esac
	done < <(tar -tvzf "$file")
	staging=$(mktemp -d)
	RESTORE_STAGING="$staging"
	trap 'rm -rf "$RESTORE_STAGING"' EXIT
	tar -C "$staging" -xzf "$file"
	[ -z "$(find "$staging" -type l -print -quit)" ] || die "备份包含符号链接"
	mkdir -p "$(path /etc/goedge-ip-cert)" "$(path /var/lib/goedge-ip-cert)"
	cp -a "$staging/etc/goedge-ip-cert/." "$(path /etc/goedge-ip-cert)/"
	cp -a "$staging/var/lib/goedge-ip-cert/." "$(path /var/lib/goedge-ip-cert)/"
	find "$(path /etc/goedge-ip-cert/credentials)" -type f -exec chmod 0600 {} +
	find "$(path /etc/goedge-ip-cert/targets.d)" -type d -exec chmod 0750 {} +
	find "$(path /etc/goedge-ip-cert/targets.d)" -type f -exec chmod 0640 {} +
	find "$(path /var/lib/goedge-ip-cert)" -type d -exec chmod 0700 {} +
	find "$(path /var/lib/goedge-ip-cert)" -type f -exec chmod 0600 {} +
	if [ "${GOEDGE_IP_CERT_TEST_MODE:-0}" != "1" ]; then
		chown -R "$SERVICE_USER:$SERVICE_GROUP" "$(path /etc/goedge-ip-cert/credentials)" "$(path /var/lib/goedge-ip-cert)"
		chown -R root:"$SERVICE_GROUP" "$(path /etc/goedge-ip-cert/targets.d)"
		chown root:"$SERVICE_GROUP" "$(path /etc/goedge-ip-cert/manager.conf)"
	fi
	shopt -s nullglob
	for config in "$(path /etc/goedge-ip-cert/targets.d)"/*.yaml; do
		core validate-config --config "$config" >/dev/null
		core status --config "$config" >/dev/null
	done
	rm -rf "$staging"
	RESTORE_STAGING=""
	trap - EXIT
	release_global_lock
	say "恢复完成；未申请证书，也未修改 GoEdge Policy。"
}

uninstall_program() {
	require_root
	local answer
	printf '确认卸载程序和 systemd service/timer？输入 YES: '
	IFS= read -r answer
	[ "$answer" = "YES" ] || { say "已取消"; return 0; }
	acquire_global_lock
	if [ -z "$ROOT_PREFIX" ]; then
		systemctl disable --now goedge-ip-cert.timer >/dev/null 2>&1 || true
		systemctl stop goedge-ip-cert.service >/dev/null 2>&1 || true
	fi
	rm -f "$(path /etc/systemd/system/goedge-ip-cert.service)" "$(path /etc/systemd/system/goedge-ip-cert.timer)" \
		"$(path /usr/local/bin/goedge-ip-cert)" "$(path /usr/local/sbin/goedge-ip-cert-manager)"
	[ -n "$ROOT_PREFIX" ] || systemctl daemon-reload
	printf '是否同时删除本地配置和 state？默认保留，输入 DELETE 删除: '
	IFS= read -r answer || true
	if [ "$answer" = "DELETE" ]; then
		rm -rf -- "$(path /etc/goedge-ip-cert)" "$(path /var/lib/goedge-ip-cert)"
	else
		say "配置和 state 已保留。GoEdge Server、Cert、Policy、Node 和数据库数据未删除。"
	fi
	release_global_lock
}

menu() {
	while true; do
		banner
		cat <<'EOF'

1. 安装 / 初始化
2. 为新网站申请 IPv4 证书
3. 查看 IP 证书状态
4. 查看日志
5. 更新程序
6. 备份 / 恢复
7. 卸载

0. 退出
EOF
		printf '\n请选择: '
		local choice
		IFS= read -r choice || return 0
		case "$choice" in
			1) install_initialize ;;
			2) apply_new_website ;;
			3) show_status ;;
			4) show_logs ;;
			5) update_program ;;
			6) backup_restore_menu ;;
			7) uninstall_program ;;
			0) return 0 ;;
			*) say "无效选择" ;;
		esac
	done
}

main() {
	case "${1:-}" in
		run-all) run_all ;;
		--version) say "$RELEASE_TAG" ;;
		"") menu ;;
		*) die "未知命令: $1" ;;
	esac
}

if [ "${GOEDGE_IP_CERT_SOURCE_ONLY:-0}" != "1" ]; then
	main "$@"
fi
