# 安装指南（Preview）

> 先在独立 GoEdge Node / Cluster测试。`v0.1.0-preview.1` 已完成 Production CA、系统信任 TLS、同 Cert ID续期和 Cluster隔离验证，但多日无人值守自然续期验收仍在进行。

## 1. 前置条件

- GoEdge v1.3.9兼容环境；
- Cert Manager部署在 EdgeAPI/MySQL所在 Control Server；
- 一个独立测试 Node / Cluster；
- 目标是唯一、规范、可公开验证的 IPv4；
- Internet能够访问目标 EdgeNode TCP 80和443；
- Control Server能够通过 HTTPS访问 Let's Encrypt；
- 已创建只匹配该 IPv4的 GoEdge HTTP Server和独立空 SSL Policy。

Cert Manager不监听80/443；HTTP-01由 EdgeNode接收并通过 EdgeAPI查询 challenge。

## 2. 创建最小 MySQL用户

先确认实际数据库名和表结构。以下示例中的 placeholder必须替换；不要把真实密码写进 shell history、Git或日志。

```sql
CREATE USER 'goedge_ip_cert'@'127.0.0.1'
  IDENTIFIED BY '<GENERATE_SECURELY_OUTSIDE_HISTORY>';

GRANT SELECT, INSERT, DELETE
ON `<GOEDGE_DATABASE>`.`edgeACMEAuthentications`
TO 'goedge_ip_cert'@'127.0.0.1';

SHOW GRANTS FOR 'goedge_ip_cert'@'127.0.0.1';
```

不得使用 `GRANT ALL`，不得复用 GoEdge现有高权限数据库用户。创建后用专用用户确认能够读取 `information_schema.TABLES/COLUMNS/STATISTICS` 和 challenge表。

## 3. 创建 GoEdge REST credential

在 EdgeAdmin使用原生 Access Key管理功能创建仅供 `goedge-ip-cert` 使用的 credential。

- 不使用管理员登录密码作为运行凭据；
- 不把 Access Key放进命令行、仓库或普通日志；
- GoEdge v1.3.9没有方法级 scope，专用 admin credential仍具有较大权限，应单独记录并支持撤销；
- EdgeAPI endpoint必须使用同机 loopback，例如 `http://127.0.0.1:8002`。

## 4. 安装用户与目录

```bash
sudo groupadd --system goedge-ip-cert
sudo useradd --system \
  --gid goedge-ip-cert \
  --home-dir /var/lib/goedge-ip-cert \
  --shell /usr/sbin/nologin \
  goedge-ip-cert

sudo install -d -o root -g goedge-ip-cert -m 0750 /etc/goedge-ip-cert
sudo install -d -o root -g goedge-ip-cert -m 0750 /etc/goedge-ip-cert/credentials
sudo install -d -o goedge-ip-cert -g goedge-ip-cert -m 0700 \
  /var/lib/goedge-ip-cert \
  /var/lib/goedge-ip-cert/account \
  /var/lib/goedge-ip-cert/rollback

sudo install -o root -g root -m 0755 \
  ./goedge-ip-cert-linux-amd64 \
  /usr/local/bin/goedge-ip-cert
```

在重复安装前先检查现有 user/group/文件，不要盲目覆盖运行状态。

## 5. 写入 credential files

默认 Preview流程使用 service-owned、0600文件，确保首次 `validate-config`/dry-run和后续 systemd service读取同一来源：

```text
/etc/goedge-ip-cert/credentials/goedge-access-key-id
/etc/goedge-ip-cert/credentials/goedge-access-key
/etc/goedge-ip-cert/credentials/mysql-dsn
```

所有文件必须为 `goedge-ip-cert:goedge-ip-cert 0600`。MySQL DSN示例：

```text
goedge_ip_cert:<PASSWORD>@tcp(127.0.0.1:3306)/<GOEDGE_DATABASE>?parseTime=true&charset=utf8mb4
```

不要把真实值粘贴到文档、issue、shell参数或 Git。也可以自行改用 systemd `LoadCredential=`，但必须同步修改 config中的 file path，并保证所有手工检查在相同 credential上下文运行。

## 6. 配置

```bash
sudo install -o root -g goedge-ip-cert -m 0640 \
  config.example.yaml \
  /etc/goedge-ip-cert/config.yaml
```

至少替换：

- `target.ipv4`
- `database.name`
- `acme.email`
- 必要时选择 Production或 Staging directory

Staging与 Production必须使用不同 `account_dir`，不能混用 account key/registration。`config.example.yaml`中的保留地址仅为占位符，未替换时会被 strict public IPv4 validator拒绝。

## 7. 配置检查与 dry-run

```bash
sudo -u goedge-ip-cert \
  /usr/local/bin/goedge-ip-cert validate-config \
  --config /etc/goedge-ip-cert/config.yaml

sudo -u goedge-ip-cert \
  /usr/local/bin/goedge-ip-cert run-once \
  --config /etc/goedge-ip-cert/config.yaml
```

核对 dry-run返回的 IPv4、Server ID、Policy ID；出现0个或多个精确 Server匹配时必须停止。

## 8. 首次签发和人工绑定

明确授权后才执行：

```bash
sudo -u goedge-ip-cert \
  /usr/local/bin/goedge-ip-cert run-once \
  --config /etc/goedge-ip-cert/config.yaml \
  --apply
```

首次签发会创建 GoEdge Cert并停在 `CERT_CREATED`，提示 Cert ID与 Policy ID。这是预期的 fail-closed行为。

1. 在 EdgeAdmin将该 Cert ID手工绑定到对应 SSL Policy；
2. 确认没有绑定到其他业务 Policy；
3. 再执行一次相同 `--apply`命令；
4. 服务只读确认绑定，并验证线上 trust chain、IP SAN和 fingerprint后进入 `ACTIVE`。

Cert Manager不会调用 `updateSSLPolicy`。

## 9. TLS验收

Production certificate应由正常系统 trust直接验证，禁止使用 insecure参数作为验收依据：

```bash
curl --proto '=https' --tlsv1.2 \
  --max-redirs 0 \
  https://YOUR_PUBLIC_IPV4/
```

同时确认线上 leaf fingerprint与 GoEdge Cert record一致，SAN类型必须是 `IP Address`。

## 10. 安装 systemd unit

先完成手工 issue/bind/TLS验收，再安装 timer：

```bash
sudo install -o root -g root -m 0644 \
  deploy/systemd/goedge-ip-cert.service \
  /etc/systemd/system/goedge-ip-cert.service

sudo install -o root -g root -m 0644 \
  deploy/systemd/goedge-ip-cert.timer \
  /etc/systemd/system/goedge-ip-cert.timer

sudo systemd-analyze verify \
  /etc/systemd/system/goedge-ip-cert.service \
  /etc/systemd/system/goedge-ip-cert.timer

sudo systemctl daemon-reload
sudo systemctl start goedge-ip-cert.service
sudo systemctl enable --now goedge-ip-cert.timer
```

检查：

```bash
systemctl status goedge-ip-cert.timer
systemctl list-timers --all | grep goedge-ip-cert
journalctl -u goedge-ip-cert.service
```

Timer每小时检查一次，未到续期窗口时安全退出；`Persistent=true`补偿停机期间错过的 calendar tick，`RandomizedDelaySec=5m`减少同时触发。

## 11. 备份与撤销

长期加密备份：

- `/etc/goedge-ip-cert/config.yaml`
- credential source files
- `/var/lib/goedge-ip-cert/state.db`
- 当前环境的 ACME account目录

`rollback/` 是含旧 certificate private key的短期故障窗口，不得进入普通备份、日志或 Git。

撤销前先停止 timer并确认 oneshot已结束，然后按依赖关系处理：

1. 保留仍在 GoEdge提供服务的证书，或先完成明确的人工替换；
2. 禁用并删除专用 REST credential；
3. `DROP USER 'goedge_ip_cert'@'127.0.0.1'`；
4. 加密归档必要 state/account后删除 Cert Manager文件和 service user。

不要直接 DELETE GoEdge证书、Policy、Server或 NodeTask表。
