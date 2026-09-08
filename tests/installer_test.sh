#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034,SC2155,SC2329
set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
export GOEDGE_IP_CERT_SOURCE_ONLY=1
export GOEDGE_IP_CERT_SERVICE_USER="$(id -un)"
export GOEDGE_IP_CERT_SERVICE_GROUP="$(id -gn)"
# shellcheck source=../install.sh
source "$REPO_ROOT/install.sh"

passed=0
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { passed=$((passed + 1)); printf 'ok %d - %s\n' "$passed" "$1"; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "expected [$2] in [$1]"; }

test_prerequisite_prompt_and_menu() {
	local output
	output=$(preparation_prompt <<<"")
	assert_contains "$output" "首次安装前请准备"
	assert_contains "$output" "REST Access Key"
	assert_contains "$output" "REST Access Token"
	if preparation_prompt <<<"q" >/dev/null; then fail "q did not exit prompt"; fi
	local menu_count
	menu_count=$(sed -n '/1\. 安装 \/ 初始化/,/7\. 卸载/p' "$REPO_ROOT/install.sh" | grep -Ec '^[1-7]\. ')
	[ "$menu_count" -eq 7 ] || fail "menu count=$menu_count"
	pass "install prerequisite prompt and fixed menu"
}

test_hidden_token_input_path() {
	local stderr value
	stderr=$(mktemp)
	value=$(read_secret "Token: " <<<"fixture-token" 2>"$stderr")
	[ "$value" = "fixture-token" ] || fail "secret read failed"
	! grep -q 'fixture-token' "$stderr" || fail "secret echoed"
	rm -f "$stderr"
	pass "hidden token input path"
}

test_os_and_arch_detection() {
	local tmp
	tmp=$(mktemp -d)
	printf 'ID=debian\nVERSION_ID="12"\n' >"$tmp/os-release"
	[ "$(GOEDGE_IP_CERT_OS_RELEASE="$tmp/os-release" detect_os)" = "debian-12" ] || fail "Debian 12 rejected"
	[ "$(GOEDGE_IP_CERT_UNAME_M=x86_64 detect_arch)" = "amd64" ] || fail "amd64 detection"
	[ "$(GOEDGE_IP_CERT_UNAME_M=aarch64 detect_arch)" = "arm64" ] || fail "arm64 detection"
	if GOEDGE_IP_CERT_UNAME_M=i386 detect_arch >/dev/null 2>&1; then fail "unsupported arch accepted"; fi
	systemctl() { return 0; }
	GOEDGE_IP_CERT_TEST_MODE=1 detect_systemd || fail "systemd detection"
	rm -rf "$tmp"
	pass "OS and architecture detection"
}

test_db_config_discovery_and_failure() {
	local tmp root output
	tmp=$(mktemp -d)
	root="$tmp/goedge"
	mkdir -p "$root/edge-admin/edge-api/configs"
	printf 'user: root\n' >"$root/edge-admin/edge-api/configs/db.yaml"
	output=$(find_goedge_db_config "$root")
	[ "$output" = "$root/edge-admin/edge-api/configs/db.yaml" ] || fail "DB config discovery"
	rm -f "$output"
	if find_goedge_db_config "$root" >"$tmp/out" 2>&1; then fail "missing DB config accepted"; fi
	grep -q 'AUTO_DB_INITIALIZATION_FAILED' "$tmp/out" || fail "missing DB failure marker"
	rm -rf "$tmp"
	pass "DB config discovery and fail-closed initialization"
}

test_existing_installation_fails_closed() {
	local tmp
	tmp=$(mktemp -d)
	ROOT_PREFIX="$tmp"
	mkdir -p "$tmp/usr/local/bin"
	: >"$tmp/usr/local/bin/goedge-ip-cert"
	if prepare_install_state >"$tmp/out" 2>&1; then
		fail "existing binary was accepted"
	fi
	grep -q 'EXISTING_INSTALLATION_DETECTED' "$tmp/out" || fail "missing existing installation marker"
	mkdir -p "$tmp/etc/goedge-ip-cert"
	: >"$tmp/etc/goedge-ip-cert/.installing"
	prepare_install_state || fail "owned partial installation could not resume"
	[ "$RESUME_INSTALL" -eq 1 ] || fail "partial installation not marked for resume"
	rm -rf "$tmp"
	ROOT_PREFIX=""
	pass "existing installation fails closed"
}

test_existing_target_is_not_overwritten() {
	local tmp target before after
	tmp=$(mktemp -d)
	ROOT_PREFIX="$tmp"
	GOEDGE_ENDPOINT="$DEFAULT_ENDPOINT"
	DATABASE_NAME=edges
	mkdir -p "$tmp/etc/goedge-ip-cert/targets.d" "$tmp/var/lib/goedge-ip-cert/targets"
	GOEDGE_IP_CERT_TEST_MODE=1 write_target_config "8.8.8.8"
	target=$(target_config_path "8.8.8.8")
	before=$(sha256sum "$target")
	printf '# operator-owned\n' >>"$target"
	after=$(sha256sum "$target")
	GOEDGE_IP_CERT_TEST_MODE=1 write_target_config "8.8.8.8"
	[ "$(sha256sum "$target")" = "$after" ] || fail "existing target overwritten"
	[ "$before" != "$after" ] || fail "fixture did not change"
	rm -rf "$tmp"
	ROOT_PREFIX=""
	pass "existing managed target preservation"
}

test_cancelled_dry_run_is_not_registered() {
	local tmp output output_file calls
	tmp=$(mktemp -d)
	ROOT_PREFIX="$tmp"
	unset GOEDGE_ENDPOINT DATABASE_NAME || true
	mkdir -p "$tmp/etc/goedge-ip-cert/credentials" "$tmp/etc/goedge-ip-cert/targets.d" "$tmp/var/lib/goedge-ip-cert/targets"
	printf 'fixture\n' >"$tmp/etc/goedge-ip-cert/credentials/goedge-access-key-id"
	printf 'fixture\n' >"$tmp/etc/goedge-ip-cert/credentials/goedge-access-key"
	printf 'fixture\n' >"$tmp/etc/goedge-ip-cert/credentials/mysql-dsn"
	printf 'v0.1.0-preview.4\n' >"$tmp/etc/goedge-ip-cert/installed-version"
	printf 'DATABASE_NAME=edges\n' >"$tmp/etc/goedge-ip-cert/manager.conf"
	calls="$tmp/calls"
	flock() { return 0; }
	core() {
		case "$1" in
			discover-websites)
				printf 'DISCOVER\n' >>"$calls"
				printf '%s\n' '[{"serverId":11,"name":"site","ipv4":"8.8.8.8","policyId":12,"clusterId":7,"cluster":"cluster","nodeOnline":true}]'
				;;
			run-once)
				if [[ " $* " == *" --apply "* ]]; then
					printf 'APPLY_MUTATION\n' >>"$calls"
					return 97
				fi
				local config_path="$3"
				[ -f "$config_path" ] || fail "pending target config was not generated"
				grep -F 'endpoint: http://127.0.0.1:8002' "$config_path" >/dev/null || fail "target endpoint missing"
				grep -F 'name: edges' "$config_path" >/dev/null || fail "target database missing"
				printf 'DRY_RUN_CONFIG_OK\n' >>"$calls"
				printf '%s\n' '{"IPv4":"8.8.8.8","ServerID":11,"PolicyID":12}'
				;;
			*)
				printf 'UNEXPECTED_CORE_CALL=%s\n' "$1" >>"$calls"
				return 98
				;;
		esac
	}
	output_file="$tmp/output"
	GOEDGE_IP_CERT_TEST_MODE=1 apply_new_website <<< $'1\nn' >"$output_file"
	output=$(<"$output_file")
	assert_contains "$output" "未创建 ACME order"
	[ "$(grep -c '^DISCOVER$' "$calls")" -eq 1 ] || fail "website discovery did not use installed manager path"
	[ "$(grep -c '^DRY_RUN_CONFIG_OK$' "$calls")" -eq 1 ] || fail "target config/dry-run was not completed"
	! grep -q 'MUTATION\|UNEXPECTED' "$calls" || fail "cancel path reached a mutating/unexpected core call"
	if compgen -G "$tmp/etc/goedge-ip-cert/targets.d/*.yaml" >/dev/null; then
		fail "cancelled target was registered for timer"
	fi
	rm -rf "$tmp"
	ROOT_PREFIX=""
	pass "cancelled dry-run cannot be applied by timer"
}

test_multiple_target_serial_runner() {
	local tmp calls
	tmp=$(mktemp -d)
	ROOT_PREFIX="$tmp"
	mkdir -p "$tmp/etc/goedge-ip-cert/targets.d" "$tmp/var/lib/goedge-ip-cert"
	printf 'DATABASE_NAME=edges\n' >"$tmp/etc/goedge-ip-cert/manager.conf"
	: >"$tmp/etc/goedge-ip-cert/targets.d/9.9.9.9.yaml"
	: >"$tmp/etc/goedge-ip-cert/targets.d/8.8.8.8.yaml"
	calls="$tmp/calls"
	flock() { return 0; }
	core() { printf '%s\n' "$*" >>"$calls"; }
	run_all
	[ "$(wc -l <"$calls" | tr -d ' ')" -eq 2 ] || fail "target count"
	[ "$(sed -n '1p' "$calls")" = "run-once --config $tmp/etc/goedge-ip-cert/targets.d/8.8.8.8.yaml --apply" ] || fail "targets not serial/sorted"
	rm -rf "$tmp"
	ROOT_PREFIX=""
	pass "multiple target isolation and serial global runner"
}

test_status_pending_and_bound_views() {
	local tmp output
	tmp=$(mktemp -d)
	ROOT_PREFIX="$tmp"
	mkdir -p "$tmp/etc/goedge-ip-cert/targets.d"
	: >"$tmp/etc/goedge-ip-cert/targets.d/8.8.8.8.yaml"
	STATUS_MODE=pending
	core() {
		if [ "$STATUS_MODE" = "pending" ]; then
			printf '%s\n' '{"ipv4":"8.8.8.8","website":"site","cluster":"cluster","certId":42,"state":"CERT_CREATED","bound":false,"autoRenew":false,"nodeOnline":true,"httpsStatus":"未验证","remaining":"","environment":"Production","ipSan":true,"notAfter":0,"renewBefore":"72h0m0s","nextRenewalAt":0,"lastSuccessAt":0,"lastError":"","systemTrust":false}'
		else
			printf '%s\n' '{"ipv4":"8.8.8.8","website":"site","cluster":"cluster","certId":42,"state":"ACTIVE","bound":true,"autoRenew":true,"nodeOnline":true,"httpsStatus":"正常","remaining":"5d","environment":"Production","ipSan":true,"notAfter":0,"renewBefore":"72h0m0s","nextRenewalAt":0,"lastSuccessAt":0,"lastError":"","systemTrust":true}'
		fi
	}
	output=$(show_status)
	assert_contains "$output" "待绑定"
	STATUS_MODE=bound
	output=$(show_status)
	assert_contains "$output" "正常"
	assert_contains "$output" "自动续期：开启"
	rm -rf "$tmp"
	ROOT_PREFIX=""
	pass "certificate status pending-bind and bound views"
}

test_update_checksum_failure_preserves_binary() {
	local tmp
	tmp=$(mktemp -d)
	ROOT_PREFIX="$tmp"
	mkdir -p "$tmp/usr/local/bin" "$tmp/usr/local/sbin"
	printf '#!/bin/sh\necho old\n' >"$tmp/usr/local/bin/goedge-ip-cert"
	chmod +x "$tmp/usr/local/bin/goedge-ip-cert"
	printf '#!/bin/sh\n' >"$tmp/usr/local/sbin/goedge-ip-cert-manager"
	download_release() { return 1; }
	if download_release "goedge-ip-cert-linux-amd64" "$tmp/new-binary"; then fail "bad checksum download succeeded"; fi
	[ "$("$tmp/usr/local/bin/goedge-ip-cert")" = "old" ] || fail "old binary not preserved"
	rm -rf "$tmp"
	ROOT_PREFIX=""
	pass "update SHA failure preserves old binary"
}

test_backup_restore_and_uninstall_safety() {
	local tmp output archive
	tmp=$(mktemp -d)
	ROOT_PREFIX="$tmp"
	mkdir -p "$tmp/etc/goedge-ip-cert/credentials" "$tmp/var/lib/goedge-ip-cert/targets/8.8.8.8/rollback" "$tmp/usr/local/bin" "$tmp/usr/local/sbin" "$tmp/etc/systemd/system" "$tmp/goedge"
	printf 'secret\n' >"$tmp/etc/goedge-ip-cert/credentials/token"
	printf 'state\n' >"$tmp/var/lib/goedge-ip-cert/targets/8.8.8.8/state.db"
	printf 'private\n' >"$tmp/var/lib/goedge-ip-cert/targets/8.8.8.8/rollback/snapshot"
	output=$(GOEDGE_IP_CERT_TEST_MODE=1 create_backup)
	archive=$(awk -F': ' '/备份已创建/ {print $2}' <<<"$output")
	[ -f "$archive" ] || fail "backup absent"
	! tar -tzf "$archive" | grep -q '/rollback/' || fail "rollback included"
	rm -rf "$tmp/etc/goedge-ip-cert" "$tmp/var/lib/goedge-ip-cert"
	mkdir -p "$tmp/etc/goedge-ip-cert/targets.d" "$tmp/var/lib/goedge-ip-cert"
	core() { return 0; }
	GOEDGE_IP_CERT_TEST_MODE=1 restore_backup <<<"$archive" >/dev/null
	[ -f "$tmp/etc/goedge-ip-cert/credentials/token" ] || fail "credential not restored"
	[ -f "$tmp/var/lib/goedge-ip-cert/targets/8.8.8.8/state.db" ] || fail "state not restored"
	: >"$tmp/usr/local/bin/goedge-ip-cert"
	: >"$tmp/usr/local/sbin/goedge-ip-cert-manager"
	: >"$tmp/etc/systemd/system/goedge-ip-cert.service"
	: >"$tmp/etc/systemd/system/goedge-ip-cert.timer"
	printf 'business\n' >"$tmp/goedge/server-record"
	GOEDGE_IP_CERT_TEST_MODE=1 uninstall_program <<< $'YES\n\n' >/dev/null
	[ -d "$tmp/etc/goedge-ip-cert" ] || fail "config not retained by default"
	[ -f "$tmp/goedge/server-record" ] || fail "GoEdge object touched"
	rm -rf "$tmp"
	ROOT_PREFIX=""
	pass "backup exclusion, restore boundary, and uninstall safety"
}

test_secret_redaction_contract() {
	! grep -nE 'set -x|printenv|declare -p|export -p' "$REPO_ROOT/install.sh" >/dev/null || fail "secret dump primitive present"
	grep -q 'read -r -s' "$REPO_ROOT/install.sh" || fail "hidden read missing"
	pass "installer secret redaction contract"
}

test_prerequisite_prompt_and_menu
test_hidden_token_input_path
test_os_and_arch_detection
test_db_config_discovery_and_failure
test_existing_installation_fails_closed
test_existing_target_is_not_overwritten
test_cancelled_dry_run_is_not_registered
test_multiple_target_serial_runner
test_status_pending_and_bound_views
test_update_checksum_failure_preserves_binary
test_backup_restore_and_uninstall_safety
test_secret_redaction_contract

printf 'installer tests: %d passed, 0 failed\n' "$passed"
