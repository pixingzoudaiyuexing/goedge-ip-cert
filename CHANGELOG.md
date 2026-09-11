# Changelog

## v1.0.0 - 2026-09-12

First stable release.

### Highlights

- Promote the independently reviewed Preview 5 lifecycle and safety behavior to Stable.
- Production unattended natural renewal is proven with the same GoEdge Cert ID, unchanged SSL Policy, isolated Node refresh and no post-renewal order storm.
- Add a Menu 2 hint for newly created GoEdge IP websites: enable HTTPS / 443 and click Save once before discovery; no certificate needs to be selected first.
- Stable update checks ignore draft and prerelease releases and accept stable `vX.Y.Z` tags only.

### Safety

- No ACME identifier/profile, CSR, HTTP-01, challenge, certificate create/update, Policy write boundary, same-Cert-ID renewal or lifecycle semantics changed from Preview 5.
- First-issuance failures remain `NEEDS_ATTENTION` and are never automatically retried by the hourly timer.
- First SSL Policy certificate binding remains manual and read-only from Cert Manager.

## v0.1.0-preview.5 - 2026-09-08

First-issuance failure safety.

### Fixed

- Persist first-issuance failures with a `needs-attention` recovery marker and expose them as `NEEDS_ATTENTION`.
- Make hourly `run-all` use an explicit timer mode that never initiates first issuance and skips failed never-issued targets.
- Normalize legacy Preview 4 `ERROR + issue + certId=0` state before it can create another ACME order.
- Require a fresh dry-run and explicit Manager confirmation before exactly one manual first-issuance retry.
- Update lego to v4.25.2 and go-jose to v4.1.4 to enforce HTTPS for ACME servers and resolve reachable dependency vulnerabilities; source builds now require Go 1.24 or newer.

### Safety

- ACTIVE certificate renewal keeps its existing persistent automatic backoff and same-Cert-ID behavior.
- `CERT_CREATED` continues to perform read-only binding checks without a second order.
- No ACME identifier/profile, CSR, HTTP-01, challenge, certificate REST, Policy, or rollback protocol changed.
- Preview 5 is not deployed to the Stage 3T-4 runtime while its Preview 4 natural-renewal acceptance is in progress.

## v0.1.0-preview.4 - 2026-09-08

Manager dry-run contract fix.

### Fixed

- Read the existing core dry-run JSON contract using `IPv4`, `ServerID`, and `PolicyID` field names.
- Run the unmanaged-target regression through the direct manager call path so Bash command substitution cannot mask `errexit` failures.

### Safety

- The regression covers discovery, pending target config creation, successful dry-run and explicit cancellation with no apply call.
- No core ACME, HTTP-01, lifecycle, Policy or rollback behavior changed.

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
