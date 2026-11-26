# MC-002 — Dependency planner

The planner validates v1 proposal shapes, rejects duplicate logical IDs and edges, absent parents, self edges and cycles, and computes deterministic topological order. Forward traversal yields affected descendants; reverse traversal yields the ancestors required by a target.

Graph.plan returns only provisional states:
- needs-verification: declared change, missing observation or stale observation.
- blocked: parent is not current or exact parent receipt/claim pins mismatch.
- reuse-candidate: caller reports current evidence; independent receipt validation is still required.

A caller must supply the complete change inventory; MC-002 cannot discover source changes, authenticate observations, compute canonical fingerprints, execute jobs or authorize reuse. A blocked exact pin requires a reviewed new proposal, not automatic rebinding. No mathematical implication is inferred by an edge.

Tests: 23 local unit tests passed (8 prior, 15 new), using jsonschema 4.26.0 available locally rather than the 4.23.0 development pin. Existing schema, example and test blob hashes matched repository bytes. Remote CI not enabled. These are software tests, not mathematical receipts.

Next: MC-003 canonical fingerprint format, evidence/receipt store, integrity checks, trusted policy lookup and authenticated observation boundary. Do not dispatch jobs from provisional plans.
