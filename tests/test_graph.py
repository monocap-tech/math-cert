import copy
import unittest

from mathcert.graph import Graph, GraphError, Observation
from test_schema import DEMO, SCHEMA

D = 'sha256:' + 'a' * 64
E = 'sha256:' + 'b' * 64


def manifest(node, *parents):
    m = copy.deepcopy(DEMO)
    m['id'] = node
    m['dependencies'] = [dict(id=p, receipt_digest=D, required_claim_digest=E)
                         for p in parents]
    return m


def fixture():
    return [manifest('A'), manifest('B'), manifest('C', 'A'),
            manifest('D', 'B', 'C'), manifest('E')]


class TestGraph(unittest.TestCase):
    def setUp(self):
        self.graph = Graph(fixture(), SCHEMA)
        self.obs = {n: Observation(D, E, True) for n in self.graph.order}

    def states(self, **kwargs):
        return {s.id: s for s in self.graph.plan(**kwargs)}

    def test_deterministic_order(self):
        self.assertEqual(self.graph.order, Graph(reversed(fixture()), SCHEMA).order)
        self.assertEqual(self.graph.order, ('A', 'B', 'C', 'D', 'E'))

    def test_affected(self):
        self.assertEqual(self.graph.affected(['A']), ('A', 'C', 'D'))
        self.assertEqual(self.graph.affected([]), ())

    def test_reuse_only_candidate(self):
        self.assertTrue(all(s.state == 'reuse-candidate' for s in self.graph.plan(self.obs)))

    def test_changed_blocks_descendants_not_unrelated(self):
        s = self.states(observations=self.obs, changed=['A'])
        self.assertEqual([s[n].state for n in 'ABCDE'],
                         ['needs-verification', 'reuse-candidate', 'blocked', 'blocked', 'reuse-candidate'])

    def test_missing_parent_observation(self):
        del self.obs['A']
        s = self.states(observations=self.obs)
        self.assertEqual(s['A'].reasons, ('missing-observation',))
        self.assertEqual(s['C'].reasons, ('parent-not-current:A',))

    def test_stale_parent(self):
        self.obs['A'] = Observation(D, E, False)
        s = self.states(observations=self.obs)
        self.assertEqual(s['A'].reasons, ('stale-observation',))
        self.assertEqual(s['C'].state, 'blocked')

    def test_exact_pins_not_rebound(self):
        for observation in (Observation(E, E, True), Observation(D, D, True)):
            self.obs['A'] = observation
            s = self.states(observations=self.obs)
            self.assertEqual(s['C'].reasons, ('parent-pin-mismatch:A',))

    def test_target_closure(self):
        self.assertEqual(tuple(self.states(targets=['D'])), ('A', 'B', 'C', 'D'))
        self.assertEqual(self.graph.plan(targets=[]), ())

    def test_missing_dependency(self):
        with self.assertRaises(GraphError):
            Graph([manifest('A', 'X')], SCHEMA)

    def test_duplicate_node(self):
        with self.assertRaises(GraphError):
            Graph([manifest('A'), manifest('A')], SCHEMA)

    def test_duplicate_edge_with_different_pins(self):
        m = manifest('B', 'A', 'A')
        m['dependencies'][1]['receipt_digest'] = E
        with self.assertRaises(GraphError):
            Graph([manifest('A'), m], SCHEMA)

    def test_self_edge_and_cycle(self):
        for rows in ([manifest('A', 'A')], [manifest('A', 'B'), manifest('B', 'A')]):
            with self.assertRaises(GraphError):
                Graph(rows, SCHEMA)

    def test_unknown_node(self):
        for kwargs in ({'targets': ['X']}, {'changed': ['X']}, {'observations': {'X': self.obs['A']}}):
            with self.assertRaises(GraphError):
                self.graph.plan(**kwargs)

    def test_invalid_observation(self):
        with self.assertRaises(GraphError):
            self.graph.plan({'A': Observation('invalid', E, True)})

    def test_input_mutation_does_not_change_graph(self):
        rows = fixture()
        graph = Graph(rows, SCHEMA)
        rows[2]['dependencies'].clear()
        self.assertEqual(graph.affected(['A']), ('A', 'C', 'D'))
