# 生产部署草案

> 这是 Stage 2 草案，不是部署授权。真实 CA、生产 DB、Policy、Certificate 和 Node refresh 尚未验证。

## 目录与用户

```text
用户:      goedge-ip-cert，无登录 shell
二进制:    /usr/local/bin/goedge-ip-cert，root:root 0755
配置:      /etc/goedge-ip-cert/config.yaml，root:goedge-ip-cert 0640
credentials: systemd LoadCredential，源文件 root:root 0600
状态:      /var/lib/goedge-ip-cert，goedge-ip-cert:goedge-ip-cert 0700
日志:      journald，只记录脱敏结构化事件
```

## MySQL 最小权限模板

用真实随机密码替换占位符，但不要把密码放在命令历史或仓库：

```sql
CREATE USER 'goedge_ip_cert'@'127.0.0.1' IDENTIFIED BY '<GENERATE_OUTSIDE_SQL_HISTORY>';
GRANT SELECT, INSERT, DELETE ON `edges`.`edgeACMEAuthentications`
  TO 'goedge_ip_cert'@'127.0.0.1';
```

MySQL 允许普通用户读取自己有权限对象的 `information_schema.COLUMNS/STATISTICS`。上线前用该专用用户执行 dry-run，确认 schema guard 能读取 metadata；不要追加全库权限。

## systemd 草案

`/etc/systemd/system/goedge-ip-cert.service`：

```ini
[Unit]
Description=GoEdge IPv4 certificate integration run
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=goedge-ip-cert
Group=goedge-ip-cert
ExecStart=/usr/local/bin/goedge-ip-cert run-once --config /etc/goedge-ip-cert/config.yaml --apply
LoadCredential=goedge-access-key-id:/etc/goedge-ip-cert/credentials/access-key-id
LoadCredential=goedge-access-key:/etc/goedge-ip-cert/credentials/access-key
LoadCredential=mysql-dsn:/etc/goedge-ip-cert/credentials/mysql-dsn
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
ReadWritePaths=/var/lib/goedge-ip-cert
UMask=0077
TimeoutStartSec=10min
```

`/etc/systemd/system/goedge-ip-cert.timer`：

```ini
[Unit]
Description=Hourly GoEdge IPv4 certificate check

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=5m
Unit=goedge-ip-cert.service

[Install]
WantedBy=timers.target
```

`Restart=` 对 oneshot timer 没有必要；失败由下一次 timer 和内部错误分类处理，避免短时间重复下单。

## 上线顺序

1. 备份 GoEdge DB、当前目标证书/Policy，以及本服务 account/state。
2. 安装但不启用 timer，先运行 `validate-config`。
3. 运行默认 dry-run，验证 loopback REST、专用 DB 权限和 schema。
4. 在另行授权的 E2E 阶段先用隔离测试目标完成 challenge、签发、同 ID 更新、Notify 和 TLS 验收。
5. 技术裁决通过后再启用 timer。

## 备份、升级与回滚

- 加密备份 `/var/lib/goedge-ip-cert/account`、`state.db` 及 systemd credential 源文件；定期恢复演练。
- 升级前停止 timer，等待当前 oneshot 结束，备份状态，再原子替换二进制并运行 dry-run。
- 应用失败时停止 timer，恢复上一二进制和 state/account 备份。
- 如果已更新 GoEdge 证书但 TLS 验收失败，应通过 EdgeAPI 恢复升级前导出的 cert PEM/key 和元数据，不能直接 UPDATE DB。
- Cert Manager 停止不影响当前 CDN 流量；已安装证书继续工作至过期。
