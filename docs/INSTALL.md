# 安装与管理指南（Preview）

> `v0.1.0-preview.3` 修复 Manager 未管理网站 dry-run 路径。隔离测试环境中的真实 Production CA、系统信任 TLS、同 Cert ID 续期和 Cluster 隔离已经验证；Stage 3T-4 多日无人值守自然续期验收仍在进行，请先在独立 Node / Cluster 使用。

## 前置条件

- Debian 12，systemd；
- Linux amd64 或 arm64；
- GoEdge v1.3.9 已运行，EdgeAPI 与 MySQL 在本机 loopback 可访问；
- Node / Cluster 已配置并在线；
- 已创建网站，网站“域名”仅填写一个规范公网 IPv4；
- 网站已启用可解析的 HTTPS SSL Policy；
- 已准备专用 GoEdge REST Access Key 与 REST Access Token。

不需要修改或重新编译 EdgeAdmin、EdgeAPI、EdgeNode、EdgeCommon，也不需要输入 Server / Policy / Node / Cluster / Cert ID。

## 安装

以 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/goedge-ip-cert/main/install.sh)
```

正常路径只要求 `GoEdge REST Access Key` 与 `GoEdge REST Access Token`。Token 不回显。GoEdge v1.3.9 API 中，这两项分别对应 `accessKeyId` 与长期 Access Key secret。core 用它们换取短期 API token；短期 token 只在内存中使用。

安装器会检查平台与 GoEdge，下载并校验 Release，创建 non-root 用户、目录、最小权限数据库账号和 systemd timer。初次安装时 targets 为空，因此不会申请证书，也不会创建 ACME order。

## MySQL 自动初始化

安装器只创建 `goedge_ip_cert@127.0.0.1`，唯一业务授权为：

```sql
GRANT SELECT, INSERT, DELETE
ON `<GOEDGE_DATABASE>`.`edgeACMEAuthentications`
TO 'goedge_ip_cert'@'127.0.0.1';
```

程序使用专用账号执行 `SHOW GRANTS` 并精确确认授权。找不到 GoEdge `db.yaml`、管理连接无权创建账号、challenge 表不存在、专用账号已存在但 credential 丢失或存在额外权限时，全部以 `AUTO_DB_INITIALIZATION_FAILED` 关闭。

安装器不会重置已有账号，不会请求 MySQL root 密码，也不会把 GoEdge 高权限账号作为 runtime credential。

## 为网站申请证书

运行管理器并选择菜单 2：

```bash
/usr/local/sbin/goedge-ip-cert-manager
```

管理器只读列出唯一身份为规范公网 IPv4、HTTPS Policy 有效、Cluster 至少有一个已安装启用 Node 的网站。IPv6、private、loopback、reserved 或多身份网站不会显示。

选择网站后先执行 core dry-run。只有 IPv4、Server ID 与 Policy ID 都和发现结果一致，且用户明确输入 `y`，才会调用 Let's Encrypt Production：

```text
identifier type = ip
profile = shortlived
challenge = HTTP-01
```

首次签发创建 GoEdge Cert 后会停在 `CERT_CREATED`。请在 EdgeAdmin 对应网站的 HTTPS 页面手工把 Cert ID 绑定到 SSL Policy。管理器不会写 SSL Policy。绑定后再次检测，通过正常系统 trust、IP SAN 和 fingerprint 验证才进入 `ACTIVE`。

## 多 IPv4 与自动续期

```text
/etc/goedge-ip-cert/targets.d/<IPv4>.yaml
/var/lib/goedge-ip-cert/targets/<IPv4>/state.db
/var/lib/goedge-ip-cert/targets/<IPv4>/account/
/var/lib/goedge-ip-cert/targets/<IPv4>/rollback/
```

每个 target 的状态、ACME account、Cert ID 与 rollback 完全隔离。timer 每小时启动全局 runner，并按文件名顺序逐个运行；全局 `flock` 禁止并发下单。续期保持 `RenewBefore=72h`，并只更新同一个 Cert ID。

```text
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=5m
AccuracySec=1m
```

## 状态与日志

菜单 3 综合本地 state、GoEdge Cert、Policy 绑定、Node、NotAfter、续期时间和 `https://IPv4` 正常系统信任结果，不使用 insecure TLS。

菜单 4 默认只显示最近 200 行 journal；只有用户明确选择才实时查看。core 与 manager 不输出 REST secret、DB 密码、PEM private key、ACME key 或 keyAuthorization。

## 更新

菜单 5 从 GitHub Releases 查询最新非 draft Preview，下载当前架构 binary、manager 与 `SHA256SUMS`。只有 SHA-256 和版本都验证通过才替换；任一替换失败会恢复旧 binary 和 manager。

更新保留 config、credential、ACME account、SQLite state 和 targets。

## 备份与恢复

菜单 6 创建 root-only 0600 备份，包含配置、REST/DB credential、ACME account、SQLite state 和 targets registry。备份含敏感凭据，必须加密保管。

普通备份排除 rollback 临时 snapshot、日志和 build/release 文件。恢复会校验 archive 路径并拒绝符号链接，只恢复 Cert Manager 配置与 state，重设权限并执行 `validate-config`；不会申请证书或修改 GoEdge Policy。

## 卸载

菜单 7 需要输入 `YES` 二次确认。它只停止并删除 Cert Manager 的 timer、service、binary 和 manager。配置/state 默认保留；只有再次明确输入 `DELETE` 才删除本地数据。

卸载绝不会删除 GoEdge Server、Cert、SSL Policy、Node 或 GoEdge DB 业务数据。

## 手工 core 命令

```bash
goedge-ip-cert validate-config --config /etc/goedge-ip-cert/targets.d/1.2.3.4.yaml
goedge-ip-cert status --config /etc/goedge-ip-cert/targets.d/1.2.3.4.yaml
goedge-ip-cert run-once --config /etc/goedge-ip-cert/targets.d/1.2.3.4.yaml
```

`run-once` 默认 dry-run，真实执行必须显式增加 `--apply`。

## 安全边界

- EdgeAPI endpoint 与 MySQL 只允许 loopback；
- GoEdge REST redirect 全部拒绝；
- SSL Policy 只读验证；
- SQLite v2 不保存 certificate private key；
- rollback 目录/文件为 0700/0600，且不进入普通备份；
- update 与 install 必须验证 SHA-256；
- credential、runtime config、SQLite、PEM、backup 和 `outputs/` 不得进入 Git。

更多细节见 [安全边界](SECURITY.md)、[架构](ARCHITECTURE.md) 与 [状态机](STATE-MACHINE.md)。
