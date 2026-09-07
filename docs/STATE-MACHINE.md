# 状态机与恢复

## 状态

```text
NEW
 -> CHALLENGE_PRESENT
 -> CERT_ISSUED
 -> CERT_CREATED
 -> POLICY_BOUND
 -> ACTIVE

ACTIVE -> RENEWING -> CHALLENGE_PRESENT -> CERT_ISSUED
       -> CERT_CREATED -> POLICY_BOUND -> ACTIVE

任一步骤可进入 ERROR，并记录 error category 与 recovery marker。
```

状态变更使用 SQLite 事务和 expected-state CAS。operation 在创建前持久化唯一 marker；敏感 PEM/key 仅存在于未完成 operation，转为 ACTIVE 时清空。

## 启动 reconciliation

1. schema guard；
2. 读取 pending challenge，只清理自己 journal 中记录的行；
3. 恢复 `CERT_ISSUED/CERT_CREATED/POLICY_BOUND` operation；
4. 对在持久化证书前中断的 operation 标记可重试错误；
5. 重新发现 Server，核对本地 server/policy/cert ID；
6. 未到续期点则无写操作，到期后创建 renew operation。

## Crash point

- challenge INSERT 后、row ID journal 前：预先保存的 operation/domain/token/createdAt 用于唯一查找；多行匹配时拒绝删除。
- cert issuance 后：PEM/key 已在 SQLite，重启直接继续，不重复 order。
- EdgeAPI cert create 后、本地 cert ID 前：使用预存唯一 marker 查找，随后读取完整证书并核对 fingerprint/expiry；不会盲目再创建。
- Policy bind 后：重启先读 Policy，已有 ref 时直接推进状态，不重复覆盖。
- renew update 后：读取同 cert ID；fingerprint/expiry 已匹配时直接推进，不创建新证书。

## 续期

160 小时证书默认在剩余 72 小时加确定性 0–10 分钟 jitter 后进入续期。systemd 每小时触发，文件锁阻止本机两个实例并发。临时错误使用 15 分钟至 6 小时的指数退避设计；schema、配置、安全和鉴权错误 fail closed，需人工修复后再运行。
