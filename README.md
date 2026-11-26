# MathCert — Mathematical Certification Engine

Problem-independent orchestration for mathematical obligations, authenticated evidence, and reproducible verification. MathCert is not a proof kernel and does not establish the truth of unformalized claims.

## Initial foundation (MC-000 / MC-001)

- [Architecture and trust boundaries](docs/architecture.md)
- [Obligation schema v1](schemas/obligation-v1.json)
- [Synthetic example](examples/obligation.demo.json)
- [Validation tests](tests/test_schema.py)

MC-002 adds a provisional dependency planner; see [planner contract](docs/dependency-planner.md). This is not an operating certification engine. No RH or Yang–Mills claim is certified. No CI workflows are enabled.

Local schema tests: `python -m pip install -r requirements-dev.txt` then `python -m unittest discover -s tests -v`.

Next: MC-003 — content-addressed evidence, canonical fingerprints and authenticated receipts.
