# 状态机与恢复

## 状态

```text
NEW
 -> CHALLENGE_PRESENT
 -> CERT_ISSUED
 -> CERT_CREATED
 -> POLICY_BOUND（只读确认管理员已绑定）
 -> ACTIVE

ACTIVE -> RENEWING -> CHALLENGE_PRESENT -> CERT_ISSUED
       -> CERT_CREATED -> POLICY_BOUND -> ACTIVE

任一步骤可进入 ERROR，并记录 error category 与 recovery marker。
```

状态变更使用 SQLite 事务和 expected-state CAS。operation 在创建前持久化唯一 marker；SQLite 只记录 certificate fingerprint/expiry，不保存 certificate PEM/private key。

## 启动 reconciliation

1. schema guard；
2. 读取 pending challenge，只清理自己 journal 中记录的行；
3. 优先处理 rollback snapshot：验证当前新证书，无法确认则恢复旧证书；
4. 恢复 `CERT_ISSUED/CERT_CREATED/POLICY_BOUND` operation；
5. 对没有内存 private key 的 `CERT_ISSUED` 标记持久 backoff，下一次重新签发；
6. 重新发现 Server，核对本地 server/policy/cert ID；
7. 未到续期点则无写操作，到期后创建 renew operation。

## Crash point

- challenge INSERT 后、row ID journal 前：预先保存的 operation/domain/token/createdAt 用于唯一查找；多行匹配时拒绝删除。
- cert issuance 后：SQLite 不含 private key；重启写入持久 backoff，到期后重新签发，防止 retry storm。
- EdgeAPI cert create 后、本地 cert ID 前：使用预存唯一 marker 查找，随后读取完整证书并核对 fingerprint/expiry；不会盲目再创建。
- 首次 Policy 未绑定：停在 `CERT_CREATED` 并提示 cert ID / policy ID；管理员手工绑定后只读确认，不写 Policy。
- renew snapshot 后、update 前：启动恢复旧证书，验证后删除 snapshot。
- renew update 后、TLS verify 前：启动优先验证当前新 fingerprint；有效则完成，无法确认则恢复旧证书。
- rollback 后旧 TLS 也无法确认：保留 snapshot 并 fail safe，下一次启动继续恢复。

## 续期

160 小时证书默认在剩余 72 小时加确定性 0–10 分钟 jitter 后进入续期。systemd 每小时触发，文件锁阻止本机两个实例并发。临时错误使用 15 分钟至 6 小时的指数退避设计；schema、配置、安全和鉴权错误 fail closed，需人工修复后再运行。
