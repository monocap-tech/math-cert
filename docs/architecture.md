# MC-000 — Architecture and trust boundaries

Status: proposed v1 design; no mathematical certification is conferred by this document.

## Purpose and jurisdiction

MathCert governs evidence and verification orchestration, not mathematical truth. Research repositories retain ownership of theorem sources and mathematical adoption. Lean or other trusted mathematical checkers decide their respective formal claims. Semantic adequacy and source-to-target mathematical identification require separate, explicitly scoped evidence.

The system must work without RH-specific identifiers or assumptions. RH F08/IV103 is a future integration pilot, not a dependency of the core.

## Units and authority

- Obligation: immutable versioned proposal of an exact claim, domain, hypotheses, conclusion, limits, source pins, dependencies, verifier and policy reference. An ID is a logical name, never a cache identity.
- Evidence: untrusted outputs until checked against the expected inputs and policy.
- Receipt: immutable attestation of verified evidence and its exact scope; acceptance requires a trusted validator and approved policy. A manifest's policy selection is only a request, never authorization.
- Adoption: separate decision by the receiving research authority, including explicit interface/hypothesis discharge; verification does not imply adoption.
- Supersession: retains historical receipts; never retroactively rewrites their scope.

Producer agents cannot grant themselves acceptance. Runner exit status, PR merge, SHA match, or artifact presence alone is insufficient. Hashes identify bytes, not correctness or provenance of authorship. Independent replay means a clean independently controlled execution and authenticated inputs; it is not necessarily an independent mathematical proof. Separate identities, access controls and policy approval must be enforced outside producer-authored files.

## Lifecycle

PROPOSED → PREFLIGHTED → VERIFIED → REPLAYED → ACCEPTED → ADOPTED.

These are distinct states, not mandatory proof categories: policy defines required evidence for a particular claim. FAILED, BLOCKED and STALE are explicit outcomes. A candidate cannot bypass missing prerequisites or be accepted solely on execution success. Acceptance and adoption must be derived from evidence, not editable status fields.

## Dependency and cache rules (MC-002/003 contract)

Edges require exact parent receipt and claim digests. Reject missing dependencies, duplicate logical IDs, self edges and cycles before executing. Resolve in deterministic topological order. For each job, bind a canonical manifest, all transitive input content (including imported sources and toolchain), parent receipts, backend implementation, environment and approved policy. The fingerprint must include a versioned canonical serialization with domain separation; define it before issuing any real receipt. Never reuse evidence from an incomplete dependency inventory. Changes invalidate the affected descendants, not the whole repo. Unknown dependency effects fail closed. Cache hits require receipt validation, not just existence. Separate producer and replay identities and use atomic publication/locks to prevent concurrent acceptance races.

## Execution and evidence

Verifiers implement preflight, execute and validate. Execute in isolated environments without ambient secrets, restricted privileges and controlled network access. Treat manifests, source code, logs, artifacts and verifier outputs as untrusted. Never execute a manifest entrypoint as shell text; dispatch through allowlisted backend adapters. Validate relative paths, prevent traversal/symlink escapes, archive extraction hazards and resource exhaustion. Evidence store must use content-addressed immutable bytes and reject hash mismatch. Preserve command, environment, source pins, declared claims, axiom report, full logs and artifact inventory as required by policy. No blanket certification from an aggregate CI status.

## Composition

An edge between accepted receipts is not proof of mathematical implication. The receiver must establish exact statement/domain/normalization compatibility, discharge hypotheses, identify quantifiers and preserve applicable limits. Use a new typed obligation for a nontrivial bridge. Do not infer global positivity, compactness, continuum existence or mass gap from restricted certificates.

## Delivery order

MC-001 proposal schema and validation fixtures; MC-002 graph/planner; MC-003 canonical fingerprints, receipt/store and invalidation; MC-004 Lean backend; MC-005 axiom and replay policy; MC-006 numerical verifiers; MC-007 isolated RH pilot; MC-008 containment and adversarial tests; MC-009 independent portability pilot. No automated workflows until a bounded execution policy is reviewed.
