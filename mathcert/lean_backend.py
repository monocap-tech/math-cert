"""MC-004: constrained Lean process adapter; results are candidate evidence only."""

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

from .registry import RegistryError, digest_bytes, fingerprint


class BackendError(RegistryError):
    pass


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class CandidateEvidence:
    fingerprint: str
    source_digest: str
    backend_digest: str
    stdout_digest: str
    stderr_digest: str
    returncode: int


def _relative_path(raw):
    if not isinstance(raw, str) or '\\' in raw or '\x00' in raw:
        raise BackendError('invalid source path')
    path = PurePosixPath(raw)
    if (not raw or path.is_absolute() or any(p in ('', '.', '..')
            for p in raw.split('/')) or path.suffix != '.lean'):
        raise BackendError('invalid Lean entrypoint')
    return path


def _read_file(root, path):
    """Reject symlink components and verify containment before reading."""
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        raise BackendError('unsafe source root')
    p = base
    for component in path.parts:
        p = p / component
        if p.is_symlink():
            raise BackendError('symlink source')
    if not p.resolve().is_relative_to(base.resolve()):
        raise BackendError('source escapes root')
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise BackendError('not a regular source file')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                return stream.read()
        finally:
            os.close(fd)
    except OSError as exc:
        raise BackendError('cannot read source') from exc


def _check_source_closure(root, declared, sources):
    """Reject additional local Lean source files and check every pinned one."""
    identities = {(s['repository'], s['commit']) for s in declared}
    if len(identities) != 1:
        raise BackendError('one pinned repository revision required')
    paths = {}
    for source in declared:
        path = _relative_path(source['path'])
        if str(path) in paths:
            raise BackendError('duplicate source path')
        paths[str(path)] = source
    present = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            if (Path(directory) / name).is_symlink():
                raise BackendError('symlink in source tree')
        for name in files:
            if name.endswith('.lean'):
                present.add((Path(directory) / name).relative_to(root).as_posix())
    if present != set(paths):
        raise BackendError('untracked or missing Lean source in working tree')
    for name, source in paths.items():
        key = (source['repository'], source['commit'], name)
        if key not in sources or _read_file(root, PurePosixPath(name)) != sources[key]:
            raise BackendError('working source differs from checked inventory')


class SubprocessRunner:
    """Owner-provided sandbox command. No ambient environment or shell.

    Deployment must supply a separately reviewed sandbox prefix that denies
    network and ambient secrets. This class cannot prove that prefix isolates.
    """

    def __init__(self, sandbox_prefix, *, timeout=120, output_limit=2_000_000):
        if (not isinstance(sandbox_prefix, tuple) or not sandbox_prefix
                or any(not isinstance(s, str) or not s or '\x00' in s
                       for s in sandbox_prefix)):
            raise BackendError('sandbox prefix is required')
        if not isinstance(timeout, (int, float)) or timeout <= 0 or output_limit < 1:
            raise BackendError('invalid execution budget')
        self.sandbox_prefix = sandbox_prefix
        self.timeout = timeout
        self.output_limit = output_limit
        self.environment_bytes = json.dumps({
            'runner': 'subprocess-v1', 'sandbox_prefix': list(sandbox_prefix),
            'timeout': timeout, 'output_limit': output_limit,
            'env': {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent'},
        }, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def run(self, binary, source, root):
        try:
            result = subprocess.run([*self.sandbox_prefix, str(binary), source],
                                    cwd=root, env={'PATH': '/usr/bin:/bin',
                                                   'HOME': '/nonexistent'},
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=self.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendError('execution failed or timed out') from exc
        if len(result.stdout) > self.output_limit or len(result.stderr) > self.output_limit:
            raise BackendError('execution output budget exceeded')
        return RunResult(result.returncode, result.stdout, result.stderr)


class LeanBackend:
    def __init__(self, binary, *, approved_backend_digest, approved_policy_digest):
        """Approval digests must come from an owner-controlled registry."""
        self.binary = Path(binary)
        self.approved_backend_digest = approved_backend_digest
        self.approved_policy_digest = approved_policy_digest

    def run(self, manifest, root, sources, environment, policy, registry, runner):
        v = manifest['verification']
        if v['backend'] != 'lean4':
            raise BackendError('not a Lean 4 obligation')
        path = _relative_path(v['entrypoint'])
        if (v['backend_digest'] != self.approved_backend_digest or
                manifest['policy']['digest'] != self.approved_policy_digest):
            raise BackendError('unapproved backend or policy')
        if self.binary.is_symlink() or not self.binary.is_file():
            raise BackendError('unsafe Lean binary')
        binary_bytes = self.binary.read_bytes()
        if digest_bytes(binary_bytes) != self.approved_backend_digest:
            raise BackendError('Lean binary digest mismatch')
        entrypoints = [s for s in manifest['sources'] if s['path'] == str(path)]
        if len(entrypoints) != 1:
            raise BackendError('entrypoint requires one pinned source')
        source = entrypoints[0]
        key = (source['repository'], source['commit'], source['path'])
        _check_source_closure(root, manifest['sources'], sources)
        disk_bytes = sources[key]
        fp = fingerprint(manifest, sources, binary_bytes, environment, policy)
        if not hasattr(runner, 'run') or getattr(runner, 'environment_bytes', None) != environment:
            raise BackendError('trusted runner environment does not match pin')
        result = runner.run(self.binary, str(path), Path(root))
        if not isinstance(result, RunResult) or type(result.returncode) is not int:
            raise BackendError('invalid runner result')
        if type(result.stdout) is not bytes or type(result.stderr) is not bytes:
            raise BackendError('invalid runner output')
        stdout = registry.put_evidence(result.stdout)
        stderr = registry.put_evidence(result.stderr)
        return CandidateEvidence(fp, digest_bytes(disk_bytes),
                                 digest_bytes(binary_bytes), stdout, stderr,
                                 result.returncode)
