# 安全边界

## 凭据

- GoEdge 使用专用 admin/user Access Key，不复用日常管理员身份。
- 配置只保存 secret 引用；secret 来自 0600 文件、systemd `LoadCredential=` 或环境变量。
- 环境变量便于测试，但生产优先 systemd credential file。
- EdgeAPI v1.3.9 没有方法级 scope。若对象属于 admin，专用身份仍具有较大权限，这是已知风险。
- Access Token 只在内存缓存，过期前刷新；认证失败最多刷新一次。

## 网络

- V1 配置强制 EdgeAPI endpoint 为 loopback。
- 生产当前 REST 为 HTTP，只能使用 `127.0.0.1`；不得跨公网发送 Access Key/Token。
- 服务不监听公网管理端口，不接管 80/443，也不位于 CDN 请求链路。

## 私钥

- ACME account key 持久保存为 0600，并通过临时文件、`fsync`、rename 原子更新 metadata。
- 新证书私钥只在签发至 GoEdge 更新的 operation 中暂存；SQLite 文件为 0600，进入 ACTIVE 后清空 operation 中的 PEM/key。
- GoEdge 是 active certificate key 的长期存储。本服务不另建永久证书私钥仓库。
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

## 日志脱敏

可记录 IPv4、cert ID、policy ID、state、CA URL、expiresAt 和错误类别。`security.Redactor` 清理已知 secret、私钥 PEM、认证 header 和 DSN 密码。日志调用方仍应只输出分类后的稳定错误，不输出原始 HTTP body 或数据库 DSN。
