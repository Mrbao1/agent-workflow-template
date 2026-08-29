---
name: use-pxpipe-proxy
description: Quarantined compatibility Skill. Do not install or start pxpipe until integrity.json has verified v4 source/tree/toolchain provenance and the marketplace entry is restored by a reviewed release.
---

# pxpipe Proxy — Quarantined

Stop. The current snapshot intentionally has no marketplace entry and its installer
must reject `provenance_status: quarantined`. Do not bypass `verify-integrity.mjs`,
invoke the vendored proxy as a provider, or reinterpret the bundle hashes as upstream
source provenance.

This distributed snapshot cannot rebuild or remove quarantine. Only candidate artifacts
from a separate externally pinned and independently reviewed release process may be
considered in a later reviewed change. After that review restores publication, the exact model allowlist must come from
user/host configuration, sensitive dashboard routes must remain authenticated, and
provider verification must use non-sensitive synthetic context.
