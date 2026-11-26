import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest

from mathcert.lean_backend import (BackendError, LeanBackend, RunResult,
                                   SubprocessRunner)
from mathcert.registry import Registry, digest_bytes
from test_schema import DEMO


class FakeRunner:
    def __init__(self, result=RunResult(0, b'Lean process exited\n', b''),
                 environment_bytes=b'locked environment'):
        self.result = result
        self.environment_bytes = environment_bytes
        self.calls = []

    def run(self, binary, source, root):
        self.calls.append((binary, source, root))
        return self.result


class TestLeanBackend(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'Proof.lean').write_bytes(b'theorem trivial_claim : True := by trivial\n')
        self.binary = self.root / 'lean-stub'
        self.binary.write_bytes(b'not a Lean binary: test fixture')
        self.manifest = copy.deepcopy(DEMO)
        self.manifest['verification']['backend'] = 'lean4'
        self.manifest['verification']['entrypoint'] = 'Proof.lean'
        self.manifest['verification']['backend_digest'] = digest_bytes(self.binary.read_bytes())
        self.environment = b'locked environment'
        self.policy = b'owner policy bytes'
        self.manifest['verification']['environment_digest'] = digest_bytes(self.environment)
        self.manifest['policy']['digest'] = digest_bytes(self.policy)
        self.manifest['sources'][0]['path'] = 'Proof.lean'
        self.manifest['sources'][0]['digest'] = digest_bytes((self.root / 'Proof.lean').read_bytes())
        s = self.manifest['sources'][0]
        self.key = (s['repository'], s['commit'], s['path'])
        self.sources = {self.key: (self.root / 'Proof.lean').read_bytes()}
        self.registry = Registry(self.root / 'evidence-store')
        self.backend = LeanBackend(self.binary,
                                   approved_backend_digest=digest_bytes(self.binary.read_bytes()),
                                   approved_policy_digest=digest_bytes(self.policy))

    def run_backend(self, runner=None):
        return self.backend.run(self.manifest, self.root, self.sources,
                                self.environment, self.policy, self.registry,
                                runner or FakeRunner())

    def test_candidate_and_evidence_stored(self):
        runner = FakeRunner()
        result = self.run_backend(runner)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(self.registry.read_evidence(result.stdout_digest),
                         b'Lean process exited\n')

    def test_failed_process_is_preserved_not_accepted(self):
        result = self.run_backend(FakeRunner(RunResult(1, b'', b'error')))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.registry.read_evidence(result.stderr_digest), b'error')

    def test_working_source_mismatch_rejected_before_run(self):
        (self.root / 'Proof.lean').write_bytes(b'changed')
        runner = FakeRunner()
        with self.assertRaises(BackendError):
            self.run_backend(runner)
        self.assertEqual(runner.calls, [])

    def test_unapproved_policy_and_binary_rejected(self):
        runner = FakeRunner()
        self.manifest['policy']['digest'] = digest_bytes(b'producer policy')
        with self.assertRaises(BackendError):
            self.run_backend(runner)
        self.manifest['policy']['digest'] = digest_bytes(self.policy)
        self.binary.write_bytes(b'substituted')
        with self.assertRaises(BackendError):
            self.run_backend(runner)
        self.assertEqual(runner.calls, [])

    def test_path_traversal_and_symlink_rejected(self):
        runner = FakeRunner()
        self.manifest['verification']['entrypoint'] = '../Proof.lean'
        with self.assertRaises(BackendError):
            self.run_backend(runner)
        self.manifest['verification']['entrypoint'] = 'Proof.lean'
        (self.root / 'Proof.lean').unlink()
        (self.root / 'Proof.lean').symlink_to(self.root / 'lean-stub')
        with self.assertRaises(BackendError):
            self.run_backend(runner)
        self.assertEqual(runner.calls, [])

    def test_runner_requires_explicit_sandbox_prefix(self):
        with self.assertRaises(BackendError):
            SubprocessRunner(())

    def test_environment_pin_rejects_different_runner_configuration(self):
        runner = FakeRunner(environment_bytes=b'other configuration')
        with self.assertRaises(BackendError):
            self.run_backend(runner)
        self.assertEqual(runner.calls, [])

    def test_process_adapter_argument_dispatch_and_clean_environment(self):
        # This wrapper is a process test, not a security sandbox or Lean.
        script = self.root / 'check.py'
        script.write_text('import os,sys\nprint(sys.argv[1])\nprint(sys.argv[2])\nprint(os.getenv("MATHCERT_TEST_SECRET", "absent"))\n')
        runner = SubprocessRunner((sys.executable, str(script)), timeout=5)
        os.environ['MATHCERT_TEST_SECRET'] = 'should-not-pass'
        try:
            result = runner.run(self.binary, 'Proof.lean', self.root)
        finally:
            del os.environ['MATHCERT_TEST_SECRET']
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'Proof.lean\n', result.stdout)
        self.assertIn(b'absent\n', result.stdout)
