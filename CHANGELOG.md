# Changelog

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
