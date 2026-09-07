# GoEdge IPv4 Certificate Integration Service

这是一个独立于 GoEdge 源码的 IPv4 ACME 证书集成服务。V1 只支持：

- 单个规范公网 IPv4；
- Let's Encrypt；
- HTTP-01；
- ACME `shortlived` Profile；
- 通过 GoEdge v1.3.9 原版 REST API 创建证书、更新同一证书 ID、绑定 Policy；
- 仅在 `edgeACMEAuthentications` 表创建和精确删除临时 challenge。

它不修改 EdgeAPI、EdgeAdmin、EdgeNode 或 EdgeCommon，不创建 `edgeACMETasks`，不直接写证书、Policy、Server 或 NodeTask 表，也不监听或代理 80/443。

## 当前阶段

Stage 2 只完成隔离代码、自动测试、fake EdgeAPI 和临时 MySQL 5.7 集成测试。尚未执行真实 CA 请求、生产 REST、生产 DB 写入、Policy 绑定或 Node 刷新。

## 命令

```bash
goedge-ip-cert validate-config --config /etc/goedge-ip-cert/config.yaml
goedge-ip-cert status --config /etc/goedge-ip-cert/config.yaml
goedge-ip-cert run-once --config /etc/goedge-ip-cert/config.yaml
```

`run-once` 默认是 dry-run，只读取配置、challenge schema、GoEdge Server/Policy/Cert 状态，不创建 order 或写入任何数据。真正执行必须显式增加：

```bash
goedge-ip-cert run-once --config /etc/goedge-ip-cert/config.yaml --apply
```

在完成生产 E2E 审批前不得使用 `--apply` 指向生产。

## 本地验证

项目以 Go 1.22.12 和 lego v4.22.2 为固定兼容基线：

```bash
go mod verify
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/goedge-ip-cert
./scripts/secret-scan.sh
```

临时 MySQL 测试需要明确传入仅指向 `stage2_test` 的 DSN：

```bash
GOEDGE_TEST_MYSQL_DSN='<temporary test DSN>' \
  go test -tags integration ./internal/challenge
```

详细设计见：

- [架构](docs/ARCHITECTURE.md)
- [安全边界](docs/SECURITY.md)
- [状态机与恢复](docs/STATE-MACHINE.md)
- [生产部署草案](docs/DEPLOYMENT-DRAFT.md)
