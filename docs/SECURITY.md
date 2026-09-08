# 安全边界

## 凭据

- GoEdge 使用专用 admin/user Access Key，不复用日常管理员身份。
- 配置只保存 secret 引用；secret 来自 0600 文件、systemd `LoadCredential=` 或环境变量。
- 环境变量便于测试；默认 Preview部署使用 service-owned 0600文件，也可在同步调整 config路径后使用 systemd `LoadCredential=`。
- EdgeAPI v1.3.9 没有方法级 scope。若对象属于 admin，专用身份仍具有较大权限，这是已知风险。
- Access Token 只在内存缓存，过期前刷新；认证失败最多刷新一次。

## 网络

- V1 配置强制 EdgeAPI endpoint 为 loopback。
- 生产当前 REST 为 HTTP，只能使用 `127.0.0.1`；不得跨公网发送 Access Key/Token。
- 服务不监听公网管理端口，不接管 80/443，也不位于 CDN 请求链路。

## 私钥

- ACME account key 持久保存为 0600，并通过临时文件、`fsync`、rename 原子更新 metadata。
- 新证书私钥只在当前进程内存持有，SQLite schema 不含 certificate PEM/key 字段。
- GoEdge 是 active certificate key 的长期存储。本服务不另建永久证书私钥仓库。
- renewal 更新前的旧证书/私钥只存在于 `/var/lib/goedge-ip-cert/rollback/<operation-id>.json`：目录 0700、文件 0600、原子写入；成功或确认回滚后删除，不进入普通备份。
- 私钥、keyAuthorization、Access Key/Token、DB DSN 不进入日志或错误报告。

## 数据库硬边界

代码中唯一允许的 GoEdge 写 SQL：

```sql
INSERT INTO edgeACMEAuthentications
  (taskId, domain, token, `key`, createdAt) VALUES (?, ?, ?, ?, ?);

DELETE FROM edgeACMEAuthentications
WHERE id=? AND taskId=? AND domain=? AND token=? LIMIT 1;
```

`taskId` 永远为 0。删除必须同时匹配插入 ID、taskId、domain 和 token。schema guard 未通过时所有写入拒绝执行；代码没有 migration、ALTER 或 CREATE 路径。

## REST redirect

GoEdge REST client 强制 `CheckRedirect = http.ErrUseLastResponse`。301、302、303、307、308 和其他 3xx 都由非 2xx 检查 fail closed；不会访问 `Location`，也不会把 Access Key body 或 `X-Edge-Access-Token` 发送到重定向目标。

## Policy

Cert Manager 没有任何 SSL Policy 写方法。它只调用 `findEnabledSSLPolicyConfig` 检查管理员已完成的 enabled cert ref；未绑定时返回 cert ID / policy ID 并停止。

## 首次签发重试

首次签发失败持久标记为 `needs-attention`。hourly timer 不会为从未成功签发的 target 创建或重试 ACME order；Preview 4 遗留首次失败 state 也会先归一化并跳过。只有 Manager 完成新的 dry-run、用户明确输入 `y` 后，才会调用一次专用人工重试模式。ACTIVE 续期仍保留持久 backoff 自动恢复。

## 日志脱敏

可记录 IPv4、cert ID、policy ID、state、CA URL、expiresAt 和错误类别。`security.Redactor` 清理已知 secret、私钥 PEM、认证 header 和 DSN 密码。日志调用方仍应只输出分类后的稳定错误，不输出原始 HTTP body 或数据库 DSN。
