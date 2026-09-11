from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {count}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "cmd/goedge-ip-cert/main.go",
    'const version = "v0.1.0-preview.5"',
    'const version = "v1.0.0"',
)

replace_once(
    "install.sh",
    'readonly RELEASE_TAG="v0.1.0-preview.5"',
    'readonly RELEASE_TAG="v1.0.0"',
)

replace_once(
    "install.sh",
    "\tcount=$(jq 'length' <<<\"$data\")\n"
    '\t[ "$count" -gt 0 ] || die "没有发现符合条件的单公网 IPv4 网站"\n'
    '\tsay "请选择需要申请 IPv4 证书的网站："',
    "\tcount=$(jq 'length' <<<\"$data\")\n"
    "\t[ \"$count\" -gt 0 ] || die $'没有发现符合条件的单公网 IPv4 网站。\\n\\n如果刚在 GoEdge 新建了 IP 网站：\\n1. 进入该网站的「HTTPS」设置\\n2. 开启 HTTPS\\n3. 设置端口 443\\n4. 点击一次「保存」（无需提前选择证书）\\n5. 然后重新进入菜单 2'\n"
    '\tsay "请选择需要申请 IPv4 证书的网站："\n'
    '\tsay "提示：如果刚在 GoEdge 新建的 IP 网站没有出现在列表中，请进入该网站的「HTTPS」设置，确认已开启 HTTPS 并设置 443 端口，然后点击一次「保存」（无需提前选择证书），再重新进入本菜单。"',
)

replace_once(
    "install.sh",
    "[.[] | select(.draft == false)][0].tag_name",
    "[.[] | select(.draft == false and .prerelease == false)][0].tag_name",
)
replace_once(
    "install.sh",
    '[[ "$latest" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+-preview\\.[0-9]+$ ]] || die "无法确认 GitHub Preview Release"',
    '[[ "$latest" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]] || die "无法确认 GitHub Stable Release"',
)

readme = Path("README.md")
text = readme.read_text()
old = (
    "> **Status: Preview (`v0.1.0-preview.5`)**\n"
    ">\n"
    "> 已在隔离测试 Node / Cluster 上真实验证 Let's Encrypt Production IPv4签发、HTTP-01、系统信任 TLS、同 Cert ID续期、GoEdge Node refresh和 Cluster隔离。多日无人值守自然续期 runtime acceptance仍在进行中。请先在独立测试 Node / Cluster 使用，不要视为 Stable或 Production Ready。"
)
new = (
    "> **Status: Stable (`v1.0.0`)**\n"
    ">\n"
    "> 已真实验证 Let's Encrypt Production IPv4 签发、HTTP-01、系统信任 TLS、同 Cert ID 续期、GoEdge Node refresh、Cluster 隔离，以及 systemd timer 自然无人值守续期；续期后连续 timer 运行未产生重复 ACME Order。"
)
if text.count(old) != 1:
    raise SystemExit("README.md: stable status block mismatch")
text = text.replace(old, new, 1)
text = text.replace(
    "  -> 创建单公网 IPv4 网站并启用 HTTPS Policy",
    "  -> 创建单公网 IPv4 网站，开启 HTTPS / 443 并在 HTTPS 设置页点击一次“保存”",
    1,
)
text = text.replace("## Preview支持范围", "## v1.0 支持范围", 1)
readme.write_text(text)

install_doc = Path("docs/INSTALL.md")
text = install_doc.read_text()
replace_title = "# 安装与管理指南（Preview）"
if text.count(replace_title) != 1:
    raise SystemExit("docs/INSTALL.md: title mismatch")
text = text.replace(replace_title, "# 安装与管理指南（v1.0.0 Stable）", 1)
old = "> `v0.1.0-preview.5` 修复从未成功签发的 target 在首次失败后被 timer 自动重试的问题。隔离测试环境中的真实 Production CA、系统信任 TLS、同 Cert ID 续期和 Cluster 隔离已经验证；Stage 3T-4 多日无人值守自然续期验收仍在进行，请先在独立 Node / Cluster 使用。"
new = "> `v1.0.0` 为首个 Stable 版本。真实 Production CA、系统信任 TLS、同 Cert ID 续期、Cluster 隔离与 Stage 3T-4 systemd timer 自然无人值守续期均已验证通过。"
if text.count(old) != 1:
    raise SystemExit("docs/INSTALL.md: version paragraph mismatch")
text = text.replace(old, new, 1)
text = text.replace(
    "- 网站已启用可解析的 HTTPS SSL Policy；",
    "- 网站已开启 HTTPS、配置 443，并在 HTTPS 设置页点击过一次“保存”（无需提前选择证书）；",
    1,
)
marker = "管理器只读列出唯一身份为规范公网 IPv4、HTTPS Policy 有效、Cluster 至少有一个已安装启用 Node 的网站。IPv6、private、loopback、reserved 或多身份网站不会显示。"
hint = marker + "\n\n如果刚在 GoEdge 新建的 IP 网站没有出现在菜单 2，请先进入该网站的「HTTPS」设置，确认已开启 HTTPS 并设置 443，然后点击一次「保存」（无需提前选择证书），再重新进入菜单 2。"
if text.count(marker) != 1:
    raise SystemExit("docs/INSTALL.md: website discovery paragraph mismatch")
text = text.replace(marker, hint, 1)
text = text.replace(
    "菜单 5 从 GitHub Releases 查询最新非 draft Preview，下载当前架构 binary、manager 与 `SHA256SUMS`。",
    "菜单 5 从 GitHub Releases 查询最新非 draft、非 prerelease Stable 版本，下载当前架构 binary、manager 与 `SHA256SUMS`。",
    1,
)
install_doc.write_text(text)

changelog = Path("CHANGELOG.md")
text = changelog.read_text()
marker = "# Changelog\n\n"
if not text.startswith(marker):
    raise SystemExit("CHANGELOG.md: header mismatch")
entry = """## v1.0.0 - 2026-09-12

First stable release.

### Highlights

- Promote the independently reviewed Preview 5 lifecycle and safety behavior to Stable.
- Production unattended natural renewal is proven with the same GoEdge Cert ID, unchanged SSL Policy, isolated Node refresh and no post-renewal order storm.
- Add a Menu 2 hint for newly created GoEdge IP websites: enable HTTPS / 443 and click Save once before discovery; no certificate needs to be selected first.
- Stable update checks ignore draft and prerelease releases and accept stable `vX.Y.Z` tags only.

### Safety

- No ACME identifier/profile, CSR, HTTP-01, challenge, certificate create/update, Policy write boundary, same-Cert-ID renewal or lifecycle semantics changed from Preview 5.
- First-issuance failures remain `NEEDS_ATTENTION` and are never automatically retried by the hourly timer.
- First SSL Policy certificate binding remains manual and read-only from Cert Manager.

"""
changelog.write_text(marker + entry + text[len(marker):])

tests = Path("tests/installer_test.sh")
text = tests.read_text().replace("v0.1.0-preview.5", "v1.0.0")
old = 'assert_contains "$output" "未创建 ACME order"\n'
new = old + '\tassert_contains "$output" "如果刚在 GoEdge 新建的 IP 网站没有出现在列表中"\n'
if text.count(old) != 1:
    raise SystemExit("tests/installer_test.sh: cancel assertion insertion mismatch")
text = text.replace(old, new, 1)
insert_before = "test_multiple_target_serial_runner() {"
test_func = r'''test_no_eligible_website_shows_https_save_hint() {
	local tmp output status
	tmp=$(mktemp -d)
	ROOT_PREFIX="$tmp"
	mkdir -p "$tmp/etc/goedge-ip-cert/targets.d" "$tmp/var/lib/goedge-ip-cert"
	printf 'DATABASE_NAME=edges\n' >"$tmp/etc/goedge-ip-cert/manager.conf"
	flock() { return 0; }
	core() {
		case "$1" in
			discover-websites) printf '%s\n' '[]' ;;
			*) return 98 ;;
		esac
	}
	set +e
	output=$(set -e; GOEDGE_IP_CERT_TEST_MODE=1 apply_new_website 2>&1)
	status=$?
	set -e
	[ "$status" -ne 0 ] || fail "empty discovery unexpectedly succeeded"
	assert_contains "$output" "没有发现符合条件的单公网 IPv4 网站"
	assert_contains "$output" "进入该网站的「HTTPS」设置"
	assert_contains "$output" "设置端口 443"
	assert_contains "$output" "点击一次「保存」（无需提前选择证书）"
	rm -rf "$tmp"
	ROOT_PREFIX=""
	pass "empty discovery explains GoEdge HTTPS save prerequisite"
}

'''
if text.count(insert_before) != 1:
    raise SystemExit("tests/installer_test.sh: function insertion marker mismatch")
text = text.replace(insert_before, test_func + insert_before, 1)
call_marker = "test_cancelled_dry_run_is_not_registered\n"
if text.count(call_marker) != 1:
    raise SystemExit("tests/installer_test.sh: call insertion marker mismatch")
text = text.replace(call_marker, call_marker + "test_no_eligible_website_shows_https_save_hint\n", 1)
tests.write_text(text)
