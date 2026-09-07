# 部署与运维说明（Preview）

> Production CA、系统信任 TLS、同 Cert ID续期和 Cluster隔离已在独立测试环境验证；多日无人值守自然续期验收仍在进行。实际安装步骤和可复制模板见 [INSTALL.md](INSTALL.md) 与 `deploy/systemd/`。本文件不是生产流量部署授权。

## 目录与用户

```text
用户:      goedge-ip-cert，无登录 shell
二进制:    /usr/local/bin/goedge-ip-cert，root:root 0755
配置:      /etc/goedge-ip-cert/config.yaml，root:goedge-ip-cert 0640
credentials: /etc/goedge-ip-cert/credentials，goedge-ip-cert:goedge-ip-cert 0600
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

## systemd模板

仓库中的正式 Preview模板：

```text
deploy/systemd/goedge-ip-cert.service
deploy/systemd/goedge-ip-cert.timer
```

下面保留核心结构用于说明；安装时使用仓库模板，并先执行 `systemd-analyze verify`。

`/etc/systemd/system/goedge-ip-cert.service`：

```ini
[Unit]
Description=GoEdge IPv4 certificate integration run
After=network-online.target
Wants=network-online.target
ConditionFileIsExecutable=/usr/local/bin/goedge-ip-cert

[Service]
Type=oneshot
User=goedge-ip-cert
Group=goedge-ip-cert
ExecStart=/usr/local/bin/goedge-ip-cert run-once --config /etc/goedge-ip-cert/config.yaml --apply
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
ReadOnlyPaths=/etc/goedge-ip-cert
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
AccuracySec=1m
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

- 加密备份 `/var/lib/goedge-ip-cert/account`、`state.db` 及 credential文件；定期恢复演练。
- `/var/lib/goedge-ip-cert/rollback` 是短期故障窗口，不进入普通定时备份；它只在停止 timer 且确认无进行中 renewal 后才能安全排除/清理。
- 升级前停止 timer，等待当前 oneshot 结束，备份状态，再原子替换二进制并运行 dry-run。
- 应用失败时停止 timer，恢复上一二进制和 state/account 备份。
- 如果已更新 GoEdge 证书但 TLS 验收失败，应通过 EdgeAPI 恢复升级前导出的 cert PEM/key 和元数据，不能直接 UPDATE DB。
- Cert Manager 停止不影响当前 CDN 流量；已安装证书继续工作至过期。
