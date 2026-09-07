# goedge-ip-cert

独立的 GoEdge 公网 IPv4 证书集成服务，通过 Let's Encrypt ACME `ip` identifier、`shortlived` profile 和 HTTP-01，为 GoEdge Server 签发并自动续期受信任的 IPv4 HTTPS 证书。

> **Status: Preview (`v0.1.0-preview.1`)**
>
> 已在隔离测试 Node / Cluster 上真实验证 Let's Encrypt Production IPv4签发、HTTP-01、系统信任 TLS、同 Cert ID续期、GoEdge Node refresh和 Cluster隔离。多日无人值守自然续期 runtime acceptance仍在进行中。请先在独立测试 Node / Cluster 使用，不要视为 Stable或 Production Ready。

## 为什么独立运行

`goedge-ip-cert` 不修改或重新编译 GoEdge：

- No EdgeAPI rebuild
- No EdgeNode rebuild
- No EdgeAdmin modification
- No EdgePlus dependency

它只使用 GoEdge v1.3.9兼容的原生 EdgeAPI REST contract，并仅为 HTTP-01临时读写 `edgeACMEAuthentications`。服务不代理用户流量、不监听或占用80/443，也不在 CDN请求路径中。

```text
Cert Manager down != GoEdge down
```

停止 Cert Manager只影响未来签发和续期；已经加载到 GoEdge的证书与业务流量继续由 EdgeNode处理。

## 架构

```text
Public IPv4
  -> Let's Encrypt
     -> ACME identifier type: ip
     -> profile: shortlived
     -> HTTP-01
        -> GoEdge EdgeNode :80
        -> EdgeAPI RPC
        -> edgeACMEAuthentications
  -> goedge-ip-cert on Control Server
     -> EdgeAPI REST create/update certificate
     -> SSL Policy read-only verification
     -> SQLite lifecycle/backoff state
  -> GoEdge native configChanged
  -> EdgeNode serves https://IPv4
```

Cert Manager建议与 EdgeAPI/MySQL运行在同一 Control Server，仅通过 loopback访问 REST和 MySQL。它不需要部署到 EdgeNode。

## Preview支持范围

支持：

- 单个规范公网 IPv4
- Let's Encrypt Production或 Staging
- ACME HTTP-01
- `shortlived` profile
- 空 Common Name、唯一 IP SAN
- 自动续期并更新同一个 GoEdge Cert ID
- systemd hourly timer
- 单实例 `flock`
- 持久 backoff和 crash recovery
- 0700/0600短期 rollback snapshot
- GoEdge原生 Node refresh

暂不支持：

- IPv6
- private/reserved IP
- multi-IP SAN
- domain + IP mixed SAN
- DNS-01 for IP
- TLS-ALPN-01
- Anycast
- Cert Manager自动修改 SSL Policy

## 首次绑定模型

V1刻意不自动写 SSL Policy：

```text
first issue
  -> create GoEdge certificate
  -> return cert ID / policy ID
  -> administrator binds once in EdgeAdmin
  -> next run verifies the binding read-only

renewal
  -> update the same cert ID
  -> GoEdge native configChanged
  -> strict TLS verification
```

GoEdge v1.3.9的 Policy update是无 revision/CAS的整对象覆盖。自动 read-modify-write存在 TOCTOU / lost-update风险，因此未绑定时服务 fail closed并要求人工处理。

## 安装

完整步骤见 [安装指南](docs/INSTALL.md)。建议顺序：

1. 创建只允许 `edgeACMEAuthentications` 的最小 MySQL用户；
2. 在 GoEdge创建专用 REST credential；
3. 创建独立 Node Cluster、Server与空 SSL Policy；
4. 安装 binary、non-root用户、配置和 credential files；
5. `validate-config` 与默认 dry-run；
6. 显式 `--apply`签发；
7. 在 EdgeAdmin手工首次绑定 Cert ID；
8. 再次运行并严格验证 TLS；
9. 最后安装/启用 systemd timer。

## 命令

```bash
goedge-ip-cert validate-config --config /etc/goedge-ip-cert/config.yaml
goedge-ip-cert status --config /etc/goedge-ip-cert/config.yaml
goedge-ip-cert run-once --config /etc/goedge-ip-cert/config.yaml
```

`run-once` 默认 dry-run，不创建 ACME order，也不写 challenge或 certificate。真实执行必须显式增加：

```bash
goedge-ip-cert run-once --config /etc/goedge-ip-cert/config.yaml --apply
```

不要在未完成独立测试、备份和授权前把 `--apply` 指向生产流量对象。

## 最小数据库权限

Cert Manager对 GoEdge数据库只需要：

```sql
SELECT, INSERT, DELETE
ON <GOEDGE_DATABASE>.edgeACMEAuthentications
```

不要授予 `GRANT ALL`，不要复用 GoEdge现有高权限数据库账户。精确 SQL模板见 [安装指南](docs/INSTALL.md#2-创建最小-mysql-用户)。

## Security / Operational Safety

- 默认 dry-run，写操作必须显式 `--apply`
- EdgeAPI endpoint强制 loopback；所有 HTTP redirect均拒绝
- strict single public IPv4 validation
- CSR Common Name为空，只允许一个 IP SAN
- certificate/key/SAN/time在写入 GoEdge前本地校验
- SQLite v2不保存 certificate PEM或 private key
- rollback目录0700、snapshot 0600，成功后删除
- persistent exponential backoff，避免 retry/order storm
- `flock(LOCK_EX | LOCK_NB)`阻止本机并发实例
- SSL Policy只读验证，不自动写入
- credentials、DSN、PEM、keyAuthorization不进入日志或 Git

详细边界见 [SECURITY.md](docs/SECURITY.md) 和 [STATE-MACHINE.md](docs/STATE-MACHINE.md)。

## 已验证与仍在验证

隔离环境已真实验证：

- Let's Encrypt Production IPv4 `shortlived` certificate issuance
- Production HTTP-01和精确 challenge cleanup
- 正常系统 trust对 `https://IPv4` 验证通过
- 同 Cert ID renewal与线上 fingerprint切换
- rollback snapshot真实创建/清理
- GoEdge Node refresh
- Test/production Cluster task隔离

仍在进行：

- 多个 hourly timer正常运行
- 自然进入 renewal window后由 timer完成无人值守 Production renewal
- renewal后多次 timer运行无 order storm

这也是本版本标记为 Preview的主要原因。

## 开发验证

兼容基线：Go 1.22.12、lego v4.22.2、GoEdge v1.3.9。

```bash
go mod verify
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/goedge-ip-cert
./scripts/secret-scan.sh
```

临时 MySQL集成测试必须使用隔离测试库：

```bash
GOEDGE_TEST_MYSQL_DSN='<temporary test DSN>' \
  go test -tags integration -count=1 ./internal/challenge
```

## 文档

- [安装指南](docs/INSTALL.md)
- [架构](docs/ARCHITECTURE.md)
- [安全边界](docs/SECURITY.md)
- [状态机与恢复](docs/STATE-MACHINE.md)
- [部署与运维说明](docs/DEPLOYMENT-DRAFT.md)
- [变更记录](CHANGELOG.md)

## License

[MIT](LICENSE)
