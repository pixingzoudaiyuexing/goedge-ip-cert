# 架构

## 固定方案

```text
systemd timer
  -> goedge-ip-cert run-once --apply --timer
      -> lego: IP identifier + shortlived + HTTP-01
      -> Challenge Store: edgeACMEAuthentications INSERT/DELETE
      -> GoEdge Client: 原版 EdgeAPI REST
          -> SSLCert create/update
          -> SSLPolicy read/verify only
          -> GoEdge 原生 NotifyUpdate/configChanged
      -> SQLite: 本服务自身状态与 crash journal
```

Challenge Adapter 是内部 package，不是额外网络进程。服务本身也没有 HTTP 管理端口。

## 依赖方向

```text
cmd -> config/security/lock -> lifecycle
lifecycle -> acme/certificate/challenge/goedge/state/scheduler
acme -> lego + challenge
challenge -> database/sql MySQL
state -> database/sql SQLite
goedge -> net/http
```

Integration Service 不 import EdgeAPI/EdgeCommon/EdgePlus。GoEdge 业务契约由 fake REST fixture 固化。

`--timer` 是调度安全边界：它只处理已建立 lifecycle 的目标，不启动首次签发，并跳过 `NEEDS_ATTENTION`。首次失败的人工重试只能由 Manager 完成 dry-run 和默认拒绝确认后，以独立模式执行一次。

## 数据所有权

| 数据 | 所有者 | 本服务写入方式 |
|---|---|---|
| ACME account key/registration | 本服务 | 0600 原子文件 |
| lifecycle/operation/pending challenge | 本服务 | 0600 SQLite；不保存 certificate private key |
| `edgeACMEAuthentications` | GoEdge DB | 唯一直接 DB Adapter |
| `edgeSSLCerts` | GoEdge | EdgeAPI REST |
| `edgeSSLPolicies` | GoEdge | Cert Manager 只读；管理员在 EdgeAdmin 手工绑定 |
| `edgeServers` | GoEdge | V1 只读发现；不自动创建 Policy |
| `edgeNodeTasks` | GoEdge | 从不直写，由 EdgeAPI NotifyUpdate 创建 |

## Server 与 Policy

Server 候选来自 `listEnabledServersMatch`，客户端必须解码 `serverNamesJSON` 并精确比较 IPv4。零个或多个准确匹配都 fail closed。V1 要求目标 Server 已有启用的 HTTPS Policy；不会静默创建采用未知 TLS 默认值的新 Policy。

Policy API 是整对象覆盖且没有 revision/CAS，客户端无法安全模拟原子增量更新。因此 V1 正式路径完全不调用 `updateSSLPolicy`。首次创建 cert 后停在 `CERT_CREATED`，错误中返回 cert ID / policy ID；管理员在 EdgeAdmin 手工绑定，下一次运行只读确认 enabled cert ref 后继续。管理员并发修改 Policy 不会触发任何 Cert Manager Policy write。

续期更新同一 cert ID 前，把旧证书和私钥保存到 0700/0600 rollback snapshot。新证书更新后必须通过真实 TLS 链、IP SAN 和 leaf fingerprint 验证；失败或启动时无法确认新证书时恢复旧证书并再次验证。
