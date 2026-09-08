# Changelog

## v0.1.0-preview.3 - 2026-09-08

Manager runtime fix.

### Fixed

- Load `GOEDGE_ENDPOINT` and `DATABASE_NAME` in the parent manager shell before website discovery command substitution.
- Cover the fresh installed-manager path from unmanaged public IPv4 discovery through generated target config, successful dry-run and explicit cancellation without apply.

### Safety

- No core ACME, HTTP-01, lifecycle, Policy or rollback behavior changed.
- Cancellation still removes the pending target config and never executes `--apply`.

## v0.1.0-preview.2 - 2026-09-08

Installer and multi-IP management preview.

### Added

- Chinese interactive `install.sh` and fixed seven-item manager menu
- Debian 12 amd64/arm64 detection and SHA-256 verified GitHub Release installation
- Automatic GoEdge v1.3.9 EdgeAPI/database discovery
- Fail-closed creation and verification of the table-scoped MySQL runtime account
- Read-only eligible website discovery with strict single-public-IPv4 filtering
- Per-target config, SQLite state, ACME account and rollback directories
- Serial multi-target timer runner protected by a global lock
- Combined certificate, binding, Node, renewal and system-trust status view
- SHA-verified transactional updates, sensitive backup/restore and safe uninstall

### Safety

- Initial installation never creates an ACME order or certificate.
- First SSL Policy binding remains manual; the manager never mutates Policy JSON.
- Existing installations, target state and GoEdge business objects are never overwritten automatically.
- Core ACME issuance, HTTP-01, lifecycle and rollback engines are unchanged.

## v0.1.0-preview.1 - 2026-09-08

First public preview.

### Highlights

- Let's Encrypt certificates for a single public IPv4 address
- ACME `ip` identifier with the `shortlived` profile
- GoEdge-native HTTP-01 routing through `edgeACMEAuthentications`
- Certificate creation and same-Cert-ID renewal through EdgeAPI REST
- Read-only SSL Policy verification with one-time manual binding
- Native GoEdge `configChanged` propagation
- Non-root systemd oneshot service and hourly timer templates
- Persistent lifecycle/backoff state, single-instance locking and rollback snapshots
- No EdgeAPI, EdgeNode, EdgeAdmin or EdgeCommon source modification

### Verified

- Let's Encrypt Production IPv4 issuance
- Production HTTP-01 and exact challenge cleanup
- System-trusted TLS for `https://IPv4`
- Empty Common Name and exact single IP SAN
- Same-Cert-ID renewal and live fingerprint change
- Rollback snapshot creation and successful cleanup
- GoEdge Node refresh
- Test/production Cluster task isolation

### Preview limitations

- Multi-day unattended natural renewal runtime acceptance is still ongoing.
- Test on a dedicated GoEdge Node and Cluster before broader use.
- IPv6, multi-IP SAN, mixed domain/IP SAN, DNS-01, TLS-ALPN-01 and Anycast are not supported.
- First certificate binding to an SSL Policy is manual by design.
- This preview is not a stable production release.
