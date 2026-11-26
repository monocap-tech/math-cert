"""MC-003: content custody and integrity checks, not mathematical acceptance."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat


class RegistryError(ValueError):
    pass


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KINDS = frozenset({"claim", "fingerprint", "evidence", "receipt"})


def _check_digest(value):
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise RegistryError("invalid SHA-256 digest")
    return value


def _canonical(value):
    """Version 1 JSON; reject ambiguous types and non-string object keys."""
    def check(item):
        if item is None or type(item) in (str, int, bool):
            return
        if type(item) is list:
            for child in item:
                check(child)
            return
        if type(item) is dict and all(type(k) is str for k in item):
            for child in item.values():
                check(child)
            return
        raise RegistryError("noncanonical JSON value")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RegistryError("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_float=lambda _: (_ for _ in ()).throw(RegistryError("JSON float")),
                          parse_constant=lambda _: (_ for _ in ()).throw(RegistryError("JSON constant")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError("invalid JSON") from exc


def digest_bytes(data):
    if not isinstance(data, bytes):
        raise RegistryError("content must be bytes")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_record(kind, value):
    if kind not in _KINDS:
        raise RegistryError("unknown digest domain")
    return digest_bytes(b"mathcert\x00v1\x00" + kind.encode("ascii") + b"\x00" + _canonical(value))


def claim_digest(manifest):
    return digest_record("claim", manifest["claim"])


def fingerprint(manifest, sources, backend, environment, policy):
    """Bind a proposal to complete checked source and toolchain bytes.

    Every source has a distinct (repository, commit, path) key. The caller
    supplies fetched bytes; this function checks digests, not remote identity
    or whether a policy/backend has external approval.
    """
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise RegistryError("unsupported manifest")
    declared = manifest["sources"]
    if type(sources) is not dict or len(sources) != len(declared):
        raise RegistryError("incomplete or extra source inventory")
    keys = [(s["repository"], s["commit"], s["path"]) for s in declared]
    if len(set(keys)) != len(keys) or set(sources) != set(keys):
        raise RegistryError("duplicate or mismatched source inventory")
    for s, key in zip(declared, keys):
        if digest_bytes(sources[key]) != _check_digest(s["digest"]):
            raise RegistryError("source digest mismatch")
    for data, expected in ((backend, manifest["verification"]["backend_digest"]),
                           (environment, manifest["verification"]["environment_digest"]),
                           (policy, manifest["policy"]["digest"])):
        if digest_bytes(data) != _check_digest(expected):
            raise RegistryError("toolchain or policy digest mismatch")
    return digest_record("fingerprint", {
        "manifest": manifest,
        "source_keys": [list(key) for key in sorted(keys)],
        "backend": digest_bytes(backend),
        "environment": digest_bytes(environment),
        "policy": digest_bytes(policy),
    })


class Registry:
    """Local immutable store. Its contents are untrusted until checked."""

    def __init__(self, root):
        self.root = Path(root)
        if self.root.is_symlink():
            raise RegistryError("symlink registry root")
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise RegistryError("invalid registry root")
        for name in ("evidence", "receipts"):
            d = self.root / name
            if d.is_symlink():
                raise RegistryError("symlink store directory")
            d.mkdir(exist_ok=True)
            if not d.is_dir():
                raise RegistryError("invalid store directory")

    def _path(self, category, digest):
        _check_digest(digest)
        if self.root.is_symlink() or not self.root.is_dir():
            raise RegistryError("unsafe registry root")
        d = self.root / category
        if d.is_symlink() or not d.is_dir():
            raise RegistryError("unsafe store directory")
        return d / digest[7:]

    def _read(self, category, digest):
        p = self._path(category, digest)
        try:
            fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise RegistryError("not a regular file")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read()
            finally:
                os.close(fd)
        except OSError as exc:
            raise RegistryError("missing or unsafe stored object") from exc
        if digest_bytes(data) != digest:
            raise RegistryError("stored object digest mismatch")
        return data

    def _put(self, category, data):
        digest = digest_bytes(data)
        p = self._path(category, digest)
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o444)
        except FileExistsError:
            if self._read(category, digest) != data:
                raise RegistryError("stored object collision")
            return digest
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            p.unlink(missing_ok=True)
            raise
        return digest

    def put_evidence(self, data):
        return self._put("evidence", data)

    def read_evidence(self, digest):
        return self._read("evidence", digest)

    def put_receipt(self, record):
        """Store a candidate record; does not assert verifier authority."""
        _receipt_shape(record)
        return self._put("receipts", _canonical(record))

    def inspect_receipt(self, digest, *, expected_obligation_id,
                        expected_fingerprint, expected_claim_digest,
                        expected_parents):
        """Check integrity and exact bindings, returning an untrusted candidate.

        All expected values must come from independently checked inputs. This
        does not authenticate an issuer, approve policy or certify a theorem.
        """
        record = _decode(self._read("receipts", digest))
        _receipt_shape(record)
        if record["obligation_id"] != expected_obligation_id:
            raise RegistryError("obligation mismatch")
        if record["fingerprint"] != _check_digest(expected_fingerprint):
            raise RegistryError("stale fingerprint")
        if record["claim_digest"] != _check_digest(expected_claim_digest):
            raise RegistryError("claim mismatch")
        if record["parent_receipts"] != expected_parents:
            raise RegistryError("parent receipt mismatch")
        for evidence in record["evidence"]:
            self.read_evidence(evidence)
        return record


def _receipt_shape(record):
    if type(record) is not dict or set(record) != {
        "version", "obligation_id", "fingerprint", "claim_digest",
        "parent_receipts", "evidence"
    } or type(record["version"]) is not int or record["version"] != 1:
        raise RegistryError("invalid candidate receipt")
    if not isinstance(record["obligation_id"], str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.-]{0,127}", record["obligation_id"]):
        raise RegistryError("invalid obligation id")
    for key in ("fingerprint", "claim_digest"):
        _check_digest(record[key])
    parents = record["parent_receipts"]
    if type(parents) is not dict or any(not isinstance(k, str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.-]{0,127}", k) for k in parents):
        raise RegistryError("invalid parents")
    for value in parents.values():
        _check_digest(value)
    evidence = record["evidence"]
    if type(evidence) is not list or any(type(x) is not str for x in evidence):
        raise RegistryError("invalid evidence inventory")
    for value in evidence:
        _check_digest(value)
    if len(set(evidence)) != len(evidence):
        raise RegistryError("duplicate evidence")


def plan_candidates(graph, manifests, registry, bindings, receipt_digests,
                    *, changed=(), targets=None):
    """Feed integrity-checked candidates to MC-002's provisional planner.

    Bindings are independently fetched bytes keyed by obligation ID, each
    containing sources, backend, environment and policy. Neither those bytes
    nor this function authenticate provenance, issuer or policy approval.
    Invalid stored receipts are stale observations; invalid bindings fail shut.
    """
    from .graph import Observation

    rows = list(manifests)
    if (len(rows) != len(graph.order) or {m['id'] for m in rows} != set(graph.order)
            or set(bindings) != set(graph.order) or
            set(receipt_digests) - set(graph.order)):
        raise RegistryError("incomplete or inconsistent obligation inventory")
    observations = {}
    for m in rows:
        n = m['id']
        parents = {d['id']: d['receipt_digest'] for d in m['dependencies']}
        if tuple(sorted((p.id, p.receipt_digest, p.claim_digest)
                        for p in graph.parents[n])) != tuple(sorted(
                            (d['id'], d['receipt_digest'], d['required_claim_digest'])
                            for d in m['dependencies'])):
            raise RegistryError("graph and manifest dependencies differ")
        b = bindings[n]
        fp = fingerprint(m, b['sources'], b['backend'], b['environment'], b['policy'])
        c = claim_digest(m)
        if n not in receipt_digests:
            continue
        d = _check_digest(receipt_digests[n])
        try:
            registry.inspect_receipt(d, expected_obligation_id=n,
                                     expected_fingerprint=fp,
                                     expected_claim_digest=c,
                                     expected_parents=parents)
            current = True
        except RegistryError:
            current = False
        observations[n] = Observation(d, c, current)
    return graph.plan(observations, changed=changed, targets=targets)
