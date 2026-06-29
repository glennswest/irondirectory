# Changelog

All notable changes to irondirectory are documented here. Format follows the
cross-project convention; the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### 2026-06-29
- **docs:** SSO surfaces (decision D7) — RHEL native Kerberos/GSSAPI; OpenShift
  via native OIDC (`iron-oidc` crate), LDAP identity provider (day-one), and
  SPNEGO proxy; self-contained (no Keycloak). Added Tier 1.5 (app SSO) and
  posix/RFC 2307 schema attrs; clarified Windows/macOS domain join under Tier 2
  and macOS LDAP/krb5 light path under Tier 1.
- **docs:** Initial project scaffolding — README, architecture & decision
  record, project CLAUDE.md work plan, changelog, `.gitignore`, and Cargo
  workspace skeleton.
- **docs:** Recorded foundational decisions (see `docs/ARCHITECTURE.md`):
  dedicated fastetcd cluster (D1), DIT-over-flat-keyspace mapping (D2), Raft
  strong consistency (D3), OpenSSL 3.x FIPS provider via the `ossl` crate (D4),
  standalone-or-Kubernetes deployment (D5), and phased client targets (D6).
