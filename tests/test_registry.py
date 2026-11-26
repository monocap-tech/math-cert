import copy
from pathlib import Path
import tempfile
import unittest

from mathcert.registry import (Registry, RegistryError, claim_digest,
                               digest_bytes, digest_record, fingerprint,
                               plan_candidates)
from mathcert.graph import Graph
from test_schema import DEMO


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Registry(Path(self.temp.name) / 'store')
        self.manifest = copy.deepcopy(DEMO)
        self.source = b'example source bytes\n'
        self.backend = b'backend source\n'
        self.environment = b'locked environment\n'
        self.policy = b'approved externally, not by this test\n'
        s = self.manifest['sources'][0]
        s['digest'] = digest_bytes(self.source)
        self.key = (s['repository'], s['commit'], s['path'])
        self.manifest['verification']['backend_digest'] = digest_bytes(self.backend)
        self.manifest['verification']['environment_digest'] = digest_bytes(self.environment)
        self.manifest['policy']['digest'] = digest_bytes(self.policy)

    def fp(self, manifest=None, sources=None, backend=None):
        return fingerprint(manifest or self.manifest,
                           {self.key: self.source} if sources is None else sources,
                           self.backend if backend is None else backend,
                           self.environment, self.policy)

    def receipt(self, evidence):
        return {'version': 1, 'obligation_id': self.manifest['id'],
                'fingerprint': self.fp(), 'claim_digest': claim_digest(self.manifest),
                'parent_receipts': {}, 'evidence': [evidence]}

    def test_canonical_order_and_domain(self):
        self.assertEqual(digest_record('claim', {'a': 1, 'b': 2}),
                         digest_record('claim', {'b': 2, 'a': 1}))
        self.assertNotEqual(digest_record('claim', {'a': 1}),
                            digest_record('receipt', {'a': 1}))
        with self.assertRaises(RegistryError):
            digest_record('claim', {'float': 0.1})

    def test_fingerprint_is_order_stable_but_sensitive_to_claim(self):
        a = self.fp()
        b = copy.deepcopy(self.manifest)
        b['claim']['statement'] += ' revised'
        self.assertNotEqual(a, self.fp(b))

    def test_fingerprint_rejects_missing_or_extra_or_changed_inputs(self):
        for sources in ({}, {self.key: b'changed'},
                        {self.key: self.source, ('x', 'y', 'z'): b'extra'}):
            with self.assertRaises(RegistryError):
                self.fp(sources=sources)
        with self.assertRaises(RegistryError):
            self.fp(backend=b'other backend')

    def test_duplicate_source_identity_fails(self):
        b = copy.deepcopy(self.manifest)
        b['sources'].append(copy.deepcopy(b['sources'][0]))
        with self.assertRaises(RegistryError):
            self.fp(b, {self.key: self.source})

    def test_evidence_immutable_and_tamper_detected(self):
        d = self.store.put_evidence(b'proof log')
        self.assertEqual(self.store.put_evidence(b'proof log'), d)
        self.assertEqual(self.store.read_evidence(d), b'proof log')
        p = self.store.root / 'evidence' / d[7:]
        p.chmod(0o600)  # Model an actor with write access to the store.
        p.write_bytes(b'tampered')
        with self.assertRaises(RegistryError):
            self.store.read_evidence(d)
        with self.assertRaises(RegistryError):
            self.store.put_evidence(b'proof log')

    def test_candidate_receipt_integrity_and_parent_binding(self):
        e = self.store.put_evidence(b'interval output')
        record = self.receipt(e)
        d = self.store.put_receipt(record)
        self.assertEqual(self.store.inspect_receipt(
            d, expected_obligation_id=self.manifest['id'], expected_fingerprint=self.fp(),
            expected_claim_digest=claim_digest(self.manifest),
            expected_parents={}), record)
        for kwargs in ({'expected_fingerprint': digest_bytes(b'other')},
                       {'expected_claim_digest': digest_bytes(b'other')},
                       {'expected_parents': {'A': digest_bytes(b'parent')}}):
            expected = dict(expected_fingerprint=self.fp(),
                            expected_obligation_id=self.manifest['id'],
                            expected_claim_digest=claim_digest(self.manifest),
                            expected_parents={})
            expected.update(kwargs)
            with self.assertRaises(RegistryError):
                self.store.inspect_receipt(d, **expected)

    def test_missing_evidence_rejects_receipt(self):
        d = self.store.put_receipt(self.receipt(digest_bytes(b'missing')))
        with self.assertRaises(RegistryError):
            self.store.inspect_receipt(d, expected_obligation_id=self.manifest['id'], expected_fingerprint=self.fp(),
                                       expected_claim_digest=claim_digest(self.manifest),
                                       expected_parents={})

    def test_receipt_cannot_self_grant_accepted_state(self):
        r = self.receipt(self.store.put_evidence(b'log'))
        r['accepted'] = True
        with self.assertRaises(RegistryError):
            self.store.put_receipt(r)

    def test_symlink_object_is_rejected(self):
        target = Path(self.temp.name) / 'outside'
        target.write_bytes(b'outside')
        d = digest_bytes(b'outside')
        (self.store.root / 'evidence' / d[7:]).symlink_to(target)
        with self.assertRaises(RegistryError):
            self.store.read_evidence(d)

    def test_duplicate_json_keys_rejected(self):
        from mathcert.registry import _decode
        with self.assertRaises(RegistryError):
            _decode(b'{"a":1,"a":2}')

    def test_planner_invalidates_changed_receipt_and_descendants(self):
        from test_schema import SCHEMA
        a = copy.deepcopy(self.manifest)
        a['id'] = 'A'
        b = copy.deepcopy(self.manifest)
        b['id'] = 'B'
        evidence = self.store.put_evidence(b'log')
        a_record = dict(self.receipt(evidence), obligation_id='A',
                        fingerprint=self.fp(a), claim_digest=claim_digest(a))
        a_digest = self.store.put_receipt(a_record)
        b['dependencies'] = [{'id': 'A', 'receipt_digest': a_digest,
                              'required_claim_digest': claim_digest(a)}]
        b_record = dict(self.receipt(evidence), obligation_id='B',
                        fingerprint=self.fp(b), claim_digest=claim_digest(b),
                        parent_receipts={'A': a_digest})
        b_digest = self.store.put_receipt(b_record)
        graph = Graph([b, a], SCHEMA)
        binding = {'sources': {self.key: self.source}, 'backend': self.backend,
                   'environment': self.environment, 'policy': self.policy}
        args = (graph, [b, a], self.store, {'A': binding, 'B': binding},
                {'A': a_digest, 'B': b_digest})
        states = {s.id: s.state for s in plan_candidates(*args)}
        self.assertEqual(states, {'A': 'reuse-candidate', 'B': 'reuse-candidate'})
        p = self.store.root / 'receipts' / a_digest[7:]
        p.chmod(0o600)
        p.write_bytes(b'bad')
        states = {s.id: s.state for s in plan_candidates(*args)}
        self.assertEqual(states, {'A': 'needs-verification', 'B': 'blocked'})
