"""MC-002: deterministic planning only; no receipt validation or execution."""
from dataclasses import dataclass
from heapq import heapify, heappop, heappush
import re
from types import MappingProxyType

from jsonschema import Draft202012Validator


class GraphError(ValueError):
    pass


@dataclass(frozen=True)
class Parent:
    id: str
    receipt_digest: str
    claim_digest: str


@dataclass(frozen=True)
class Observation:
    """Caller-supplied observation, NOT authenticated evidence."""
    receipt_digest: str
    claim_digest: str
    current: bool


@dataclass(frozen=True)
class Step:
    id: str
    state: str
    reasons: tuple[str, ...]


class Graph:
    def __init__(self, manifests, schema):
        validator = Draft202012Validator(schema)
        parents = {}
        for m in manifests:
            validator.validate(m)
            node = m['id']
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,127}', node):
                raise GraphError(f'invalid id: {node!r}')
            if node in parents:
                raise GraphError(f'duplicate id: {node}')
            deps = tuple(sorted((Parent(d['id'], d['receipt_digest'],
                                        d['required_claim_digest'])
                                 for d in m['dependencies']), key=lambda p: p.id))
            if len({p.id for p in deps}) != len(deps):
                raise GraphError(f'duplicate dependency: {node}')
            if any(p.id == node for p in deps):
                raise GraphError(f'self dependency: {node}')
            parents[node] = deps
        children = {node: set() for node in parents}
        for node, deps in parents.items():
            for p in deps:
                if p.id not in parents:
                    raise GraphError(f'missing dependency: {node} -> {p.id}')
                for digest in (p.receipt_digest, p.claim_digest):
                    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                        raise GraphError(f'invalid parent digest: {node} -> {p.id}')
                children[p.id].add(node)
        counts = {n: len(d) for n, d in parents.items()}
        ready = [n for n, count in counts.items() if count == 0]
        heapify(ready)
        order = []
        while ready:
            node = heappop(ready)
            order.append(node)
            for child in sorted(children[node]):
                counts[child] -= 1
                if counts[child] == 0:
                    heappush(ready, child)
        if len(order) != len(parents):
            raise GraphError('cycle or cycle-dependent nodes: ' +
                             ', '.join(sorted(n for n, c in counts.items() if c)))
        self.parents = MappingProxyType(parents)
        self.children = MappingProxyType({n: frozenset(c) for n, c in children.items()})
        self.order = tuple(order)

    def _closure(self, roots, reverse=False):
        pending = list(roots)
        seen = set()
        while pending:
            n = pending.pop()
            if n not in self.parents:
                raise GraphError(f'unknown id: {n}')
            if n in seen:
                continue
            seen.add(n)
            pending.extend(p.id for p in self.parents[n]) if reverse else pending.extend(self.children[n])
        return seen

    def affected(self, changed):
        """Changed nodes and all descendants, in topological order."""
        selected = self._closure(changed)
        return tuple(n for n in self.order if n in selected)

    def plan(self, observations=None, changed=(), targets=None):
        """Provisional plan. Even reuse candidates require MC-003 validation.

        Missing/stale parents block children. A new parent receipt does not
        silently replace a child's exact pins. Replan after each new receipt.
        Caller must supply a complete change inventory; no automatic detection.
        """
        observations = dict(observations or {})
        for n, o in observations.items():
            if n not in self.parents:
                raise GraphError(f'unknown observation: {n}')
            if not isinstance(o, Observation) or type(o.current) is not bool:
                raise GraphError(f'invalid observation: {n}')
            if any(not isinstance(d, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', d)
                   for d in (o.receipt_digest, o.claim_digest)):
                raise GraphError(f'invalid observation digest: {n}')
        affected = set(self.affected(changed))
        selected = set(self.order) if targets is None else self._closure(targets, reverse=True)
        steps = {}
        for n in self.order:
            if n not in selected:
                continue
            blockers = []
            for p in self.parents[n]:
                if steps[p.id].state != 'reuse-candidate':
                    blockers.append(f'parent-not-current:{p.id}')
                elif (observations[p.id].receipt_digest, observations[p.id].claim_digest) != (p.receipt_digest, p.claim_digest):
                    blockers.append(f'parent-pin-mismatch:{p.id}')
            if blockers:
                steps[n] = Step(n, 'blocked', tuple(blockers))
            elif n in affected:
                steps[n] = Step(n, 'needs-verification', ('affected-by-change',))
            elif n not in observations:
                steps[n] = Step(n, 'needs-verification', ('missing-observation',))
            elif not observations[n].current:
                steps[n] = Step(n, 'needs-verification', ('stale-observation',))
            else:
                steps[n] = Step(n, 'reuse-candidate', ('requires-receipt-validation',))
        return tuple(steps.values())
