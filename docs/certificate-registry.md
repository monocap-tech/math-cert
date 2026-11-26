# MC-003 — Evidence registry and candidate receipts

This module stores immutable evidence bytes by SHA-256 and stores canonical JSON candidate receipts by SHA-256. It makes **integrity and staleness** inspectable; it does not certify mathematical claims.

`digest_record(kind, value)` hashes UTF-8 JSON serialized with sorted object keys, compact separators, no floats or non-string object keys, preceded by the domain prefix `mathcert\0v1\0{kind}\0`. This is MathCert canonical JSON **v1**, not RFC 8785. The prefix separates claim, fingerprint and receipt domains. Evidence bytes use plain SHA-256. The version must change if encoding rules change. Reject duplicate keys when decoding untrusted JSON.

`fingerprint(manifest, sources, backend, environment, policy)` checks that every declared source has exactly one matching `(repository, commit, path)` byte input, checks its SHA-256, and checks backend, environment and policy byte digests. It binds the entire versioned manifest, including exact parent pins and outputs, plus the complete checked inventory. It does not establish that the Git commit contains the supplied bytes or that a policy was approved by an independent authority.

Candidate receipt fields: `version`, `obligation_id`, `fingerprint`, `claim_digest`, `parent_receipts` (ID to exact parent receipt digest) and `evidence` (array of exact evidence byte digests). The store disallows an editable `accepted` or `adopted` field. `inspect_receipt` checks stored byte integrity, exact expected obligation, fingerprint, claim and parents, then rehashes all named evidence. The caller must derive expected values from independently resolved inputs.

`plan_candidates` passes only integrity-checked candidate observations to MC-002. Corrupt or stale records become `needs-verification`, blocking descendants. Missing records remain missing; changed obligations still use MC-002's affected closure. `reuse-candidate` remains provisional. A source pin changing to a new version requires a reviewed new manifest, and changed parent receipt pins never rebind automatically.

The local store uses exclusive file creation and refuses symlink object reads. It does not supply cryptographic issuer authentication, trusted policy lookup, remote source authentication, authorization, cross-process acceptance locks or atomic multi-object transactions. A writer with access to its root can modify files. MC-004/005 must provide trusted validator results and independent replay before any acceptance transition. A trusted deployment must control the store directory and publication permissions independently of producers.

Run `python -m unittest discover -s tests -v`. The tests check deterministic encoding, input binding, byte corruption, missing evidence, stale propagation and parent mismatch. They are software checks only.
