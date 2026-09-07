# 架构

## 固定方案

```text
systemd timer
  -> goedge-ip-cert run-once --apply
      -> lego: IP identifier + shortlived + HTTP-01
      -> Challenge Store: edgeACMEAuthentications INSERT/DELETE
      -> GoEdge Client: 原版 EdgeAPI REST
          -> SSLCert create/update
          -> SSLPolicy read/update/read-back
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

## 数据所有权

| 数据 | 所有者 | 本服务写入方式 |
|---|---|---|
| ACME account key/registration | 本服务 | 0600 原子文件 |
| lifecycle/operation/pending challenge | 本服务 | 0600 SQLite |
| `edgeACMEAuthentications` | GoEdge DB | 唯一直接 DB Adapter |
| `edgeSSLCerts` | GoEdge | EdgeAPI REST |
| `edgeSSLPolicies` | GoEdge | EdgeAPI REST |
| `edgeServers` | GoEdge | V1 只读发现；不自动创建 Policy |
| `edgeNodeTasks` | GoEdge | 从不直写，由 EdgeAPI NotifyUpdate 创建 |

## Server 与 Policy

Server 候选来自 `listEnabledServersMatch`，客户端必须解码 `serverNamesJSON` 并精确比较 IPv4。零个或多个准确匹配都 fail closed。V1 要求目标 Server 已有启用的 HTTPS Policy；不会静默创建采用未知 TLS 默认值的新 Policy。

Policy API 是整对象覆盖且没有 revision/CAS。客户端执行第一次读取、第二次读取一致性检查、只追加目标 cert ref、写入和完整 read-back。该机制能发现读取期间和写入后的漂移，但 GoEdge v1.3.9 无法原子阻止“第二次读取后、更新前”的管理员写入。生产操作必须避免同时编辑目标 Policy；未来只有 EdgeAPI 提供 CAS/增量接口才能彻底消除该竞态。
