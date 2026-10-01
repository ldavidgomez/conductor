"""Hermetic negative controls (H1-H51) for the real-subscription live harness.

Nothing here uses a real provider, the Claude CLI, credentials, the network or inference.
Sandboxes run through ``pytester`` in a subprocess with a tripwire plugin (``-p``) that is
armed *before* the target module is imported, so gate variables can be simulated safely; the
real adapters run only over fakes, with every process, network and SDK-process boundary armed.

Traceability (design H-number -> tests in this file)
====================================================

H1  neither gate ................ ``TestSandboxGates::test_h1_neither_gate``
H2  CI expression + fake key .... ``TestSandboxGates::test_h2_ci_expression_deselects``
H3  ``-m real_api``, no env ..... ``TestSandboxGates::test_h3_marker_only``
H4  env only, hook active ....... ``TestSandboxGates::test_h4_env_only_hook_skips``
H5a ``--noconftest`` ............ ``TestSandboxIsolation::test_h5a_noconftest``
H5b ``--confcutdir`` ............ ``TestSandboxIsolation::test_h5b_confcutdir``
H5c alternate rootdir ........... ``TestSandboxIsolation::test_h5c_other_rootdir``
H5d isolation ok, CLI missing ... ``TestSandboxIsolation::test_h5d_isolation_passes_cli_missing``
H5e env only, ``--noconftest`` .. ``TestSandboxGates::test_h5e_env_only_noconftest``
H6  prerequisites one at a time . ``TestSandboxPrerequisites::test_h6_prerequisite_fails_closed``
H7  simulated xdist worker ...... ``TestSandboxGates::test_h7_xdist_worker``
H8  helper reuse / marker expr .. ``TestHelperReuse::*`` and
                                  ``TestSandboxGates::test_h8_marker_expression_sandbox_pair``
H9  readiness stub .............. ``TestSandboxPrerequisites::test_h9_readiness_stub_*``
H10 zero-skip plugin (i)-(vi) ... ``TestZeroSkipSandbox::*``, ``TestZeroSkipUnit::*``
H11 pure helpers ................ ``TestIsolationStatic``, ``TestSourceTree``, ``TestClassifier``,
                                  ``TestEvidence``, ``TestCanary``, ``TestModel``, ``TestQuota``,
                                  ``TestCliClass``, ``TestStateMachine``, ``TestAggregation``
H12 private-API pin ............. ``TestPrivateApiPins::*``, ``TestAdapterStructure::*``,
                                  ``TestReporterPins::*`` (the private pytest reporter state)
H13 example pin ................. ``TestExamplePin::*``
H14 runbook contract ............ ``TestRunbookReferences::*`` (checker, then the real runbook)
H15 descendants ................. ``TestDescendants::*``
H16 passive observer ............ ``TestObserver::*``
H17 ``_file_console`` preflight . ``TestSandboxPrerequisites::test_h17_file_console_preflight``
H18 cancellation contract ....... ``TestCancellationContract::*`` (case wrapper and descendant
                                  check), ``TestRealInferenceAdapters::test_an_interrupt_at_the_*``
H19 outcome precedence .......... ``TestOutcomePrecedence::*``
H20 ``canary_scan`` evidence .... ``TestCanaryScanEvidence::*``, ``TestEvidenceContract::*``,
                                  ``TestRealL0Adapter``, ``TestRealInferenceAdapters``
H21 private logs, output surface  ``TestPrivateLogCapture::*``, ``TestOutputSurface::*``,
                                  ``TestAuthorizedCommands::*``
H22 stream names ................ ``TestEveryRequiredStreamIsScanned::*``
H23 L2 aggregate billing ........ ``TestRealInferenceAdapters::test_l[12]_aggregate_*``
H24 structural-test tripwires ... ``TestStructuralTripwires::*``, ``TestAdapterStructure::*``
H25 probe accounting ............ ``TestRealInferenceAdapters::test_probe_counts_per_case``,
                                  ``...::test_official_total_is_five_*``
H26 stale-status guard .......... ``TestStaleStatusGuard::*``
H27 report sanitizer (failures) . ``TestReportSanitizer::*``
H28 KeyboardInterrupt sanitizer . ``TestInterruptSanitizer::*``
H29 unexpected / cancellation ... ``TestExceptionRendering::*``
H30 warnings .................... ``TestWarnings::*``
H31 exact command output matrix . ``TestOutputMatrix::*`` (bash, ``pipefail``, ``tee``)
H32 fallback evidence ........... ``TestFallbackEvidence::*``
H33 ``cleanup_failed`` schema ... ``TestCleanupSchema::*``, ``TestEvidenceContract::*``
H34 stale-literal hygiene ....... ``TestStaleLiteralHygiene::*``
H35 collection / setup output ... ``TestCollectionMatrix::*`` (Class S, exact pipeline)
H36 pre-reporter failures ....... ``TestPreReporterFailures::*`` (Class S)
H37 runbook discard / candidate .. ``TestRunbookStatements::*``, ``TestRunbookReferences::*``
H38 run-level evidence .......... ``TestRunLevelEvidence::*`` (Class R),
                                  ``TestTwoPathInvariant::*``,
                                  ``TestScratchReplay::*`` (Class S)
H39 pipeline / inherited config . ``TestInheritedConfiguration::*`` (Class S)
H40 classifier grammar .......... ``TestClassifierGrammar::*``
H41 builder hermeticity audit ... ``TestBuilderAudit::*``
H42 classifier entry point ...... ``TestClassifierEntryPoint::*`` (Class C)
H43 registration window ......... ``TestRegistrationBoundaries::*`` (Class R)
H44 isolation controls .......... ``TestIsolationControls::*``, ``TestEndToEnd::*read_git_state*``
H45 Python / colour / entry point  ``TestInheritedPythonColourAndEntryPoints::*`` (Class S)
H46 diagnostics fields .......... ``TestEndToEnd::*diagnostics*``, ``*validators``
H47 four outcomes, three records  ``TestFourOutcomes::*``, ``TestEndToEnd::*`` (end to end)
H48 operator shell gate ......... ``TestShellGate::*`` (bash and zsh, stand-ins and the real
                                  classifier)
H49 classifier startup .......... ``TestClassifierStartup::*`` (Class C)
H50 static head order ........... ``TestClassifierHeadStatic::*``
H51 literal grammar tables ...... ``TestGrammarTables::*``

Also: ``TestAdapterSeams`` (fakes), ``TestModuleShape`` (AST guards),
``TestSandboxPrerequisites::test_live_tests_build_real_adapters_and_fail_closed_on_prerequisite``.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import importlib
import importlib.metadata
import inspect
import io
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tokenize
import types
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from conductor.exceptions import ProviderError
from tests.test_integration import test_claude_agent_sdk_subscription_real as lm

REPO_ROOT = Path(__file__).resolve().parents[2]
SANDBOX_INI = "[pytest]\nmarkers =\n    real_api: opt-in real API tests\n"
ROOT_CONFTEST = REPO_ROOT / "tests" / "conftest.py"
LIVE_MODULE = Path(lm.__file__).resolve()
CANARY = lm.make_canary("0123456789abcdef0123456789abcdef")
GIT_SHA = "0123456789abcdef0123456789abcdef01234567"
FACTS = {
    "date_utc": "2026-09-30T00:00:00Z",
    "host_os": "Darwin",
    "python_version": "3.14.7",
    "sdk_version": "0.2.87",
}


# ============================================================================
# Fakes and helpers
# ============================================================================


class FakeReporter:
    def __init__(self, skipped: Sequence[object] = ()) -> None:
        self.stats: dict[str, list[object]] = {"skipped": list(skipped)}
        self._keyboardinterrupt_memo: object | None = None


class FakePluginManager:
    def __init__(self, reporter: object | None) -> None:
        self.plugins: dict[str, object] = {}
        if reporter is not None:
            self.plugins["terminalreporter"] = reporter

    def get_plugin(self, name: str) -> object | None:
        return self.plugins.get(name)

    def register(self, plugin: object, name: str) -> None:
        self.plugins[name] = plugin


def make_config(
    markexpr: str | None = "real_api",
    *,
    numprocesses: int | None = None,
    reporter: object | None = True,
) -> Any:
    def getoption(name: str, *args: object) -> object:
        if name == "markexpr":
            return markexpr
        raise ValueError(name)

    return SimpleNamespace(
        option=SimpleNamespace(markexpr=markexpr, numprocesses=numprocesses),
        getoption=getoption,
        hook=SimpleNamespace(pytest_keyboard_interrupt=object()),
        pluginmanager=FakePluginManager(FakeReporter() if reporter is True else reporter),
    )


@pytest.fixture
def gates_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(lm.GATE_ENV, "1")
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)


def relabel(fn: Any, filename: Path) -> Callable[..., Any]:
    """Copy of ``fn`` whose code claims to come from ``filename`` (closure preserved)."""
    code = fn.__code__.replace(co_filename=str(filename))
    return types.FunctionType(code, fn.__globals__, fn.__name__, fn.__defaults__, fn.__closure__)


def as_conftest_fn(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Return a copy of ``fn`` whose code claims to come from the repo's ``tests/conftest.py``."""
    return relabel(fn, ROOT_CONFTEST)


def clean_streams() -> dict[str, object]:
    return dict.fromkeys(lm.REQUIRED_STREAMS, "")


def raises_outcome(outcome: lm.Outcome) -> Any:
    return pytest.raises(lm.HarnessFailure, check=lambda exc: exc.outcome == outcome)


# ============================================================================
# Pytester sandbox machinery: one builder, three classes (design section 10)
# ============================================================================
#
# Class S (scratch-only): the scenario, conftest and plugin files are generated in the sandbox,
#   import nothing from the live module, ``conductor`` or ``claude_agent_sdk`` (an AST check on
#   every written file), and the repository conftest is never loaded.
# Class R (real code under test): the gate fixture, ``fail_closed``, the evidence plugin and the
#   sanitizer are the code under test, run over complete fake adapters; Layer 2 seam recorders.
# Class C (classifier entry point): the real module run as a script, no pytest process.
#
# Layer 1 is a stdlib-only plugin loaded as the first ``-p`` argument and armed at import; each
# replacement records one fixed identifier, raises, and never calls through.  Layer 2 (Class R
# only) records the provider and SDK seams the same way.  The child environment is constructed,
# not filtered (S9), and every run asserts zero tripwire hits.

LAYER1_NAMES = (
    "subprocess.Popen",
    "os.posix_spawn",
    "os.posix_spawnp",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.system",
    "os.popen",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "BaseEventLoop.subprocess_exec",
    "BaseEventLoop.subprocess_shell",
    "socket.connect",
    "socket.connect_ex",
    "socket.create_connection",
    "socket.getaddrinfo",
)
SEAM_NAMES = (
    "anyio.open_process",
    "ClaudeSDKClient.connect",
    "claude_agent_sdk.query",
    "ClaudeAgentSdkProvider.execute",
    "ClaudeAgentSdkProvider.validate_connection",
    "ClaudeAgentSdkProvider._check_auth_readiness",
    "_run_auth_status_subprocess",
)
TRIPWIRE_NAMES = LAYER1_NAMES + SEAM_NAMES

LAYER1_PLUGIN = '''
"""Layer 1 (stdlib only): armed at import; records an identifier, raises, never calls through."""
import asyncio
import asyncio.base_events
import os
import socket
import subprocess
import sys

HITS = os.path.join(os.getcwd(), "tripwire_hits.txt")
AUDIT = os.path.join(os.getcwd(), "modules_audit.txt")
ORIGINALS = {}  # identifier -> [owner, attribute, original]; held only to restore, never called
FORBIDDEN = ("live_module_under_test", "tests.", "claude_agent_sdk", "conductor")


def _record(name):
    with open(HITS, "a") as handle:
        handle.write(name + "\\n")


def _arm(owner, attr, name):
    if not hasattr(owner, attr):
        return
    ORIGINALS[name] = [owner, attr, getattr(owner, attr)]

    def tripwire(*args, **kwargs):
        _record(name)
        raise AssertionError("tripwire: " + name)

    setattr(owner, attr, tripwire)


def _arm_all():
    _arm(subprocess.Popen, "__init__", "subprocess.Popen")
    for attr in ("posix_spawn", "posix_spawnp", "execv", "execve", "execvp", "execvpe",
                 "execl", "execle", "execlp", "execlpe", "system", "popen"):
        _arm(os, attr, "os." + attr)
    _arm(asyncio, "create_subprocess_exec", "asyncio.create_subprocess_exec")
    _arm(asyncio, "create_subprocess_shell", "asyncio.create_subprocess_shell")
    loop = asyncio.base_events.BaseEventLoop
    _arm(loop, "subprocess_exec", "BaseEventLoop.subprocess_exec")
    _arm(loop, "subprocess_shell", "BaseEventLoop.subprocess_shell")
    _arm(socket.socket, "connect", "socket.connect")
    _arm(socket.socket, "connect_ex", "socket.connect_ex")
    _arm(socket, "create_connection", "socket.create_connection")
    _arm(socket, "getaddrinfo", "socket.getaddrinfo")


_arm_all()  # at import: before any scratch module, conftest, plugin or entry-point plugin


def pytest_sessionfinish(session, exitstatus):
    seen = sorted(m for m in sys.modules if m == "tests" or m.startswith(FORBIDDEN))
    with open(AUDIT, "w") as handle:
        handle.write("\\n".join(seen))
    while ORIGINALS:
        _name, (owner, attr, original) = ORIGINALS.popitem()
        setattr(owner, attr, original)
'''

SEAM_PLUGIN = '''
"""Layer 2 (Class R only): the provider and SDK seams record, raise and never call through."""
import functools
import os

HITS = os.path.join(os.getcwd(), "tripwire_hits.txt")
_saved = []


def _arm(owner, attr, name):
    original = getattr(owner, attr)

    @functools.wraps(original)
    def recorder(*args, **kwargs):
        with open(HITS, "a") as handle:
            handle.write(name + "\\n")
        raise AssertionError("tripwire: " + name)

    _saved.append((owner, attr, original))
    setattr(owner, attr, recorder)


def pytest_sessionstart(session):
    targets = []
    try:
        import anyio

        targets.append((anyio, "open_process", "anyio.open_process"))
    except ImportError:
        pass
    try:
        import claude_agent_sdk

        targets.append((claude_agent_sdk.ClaudeSDKClient, "connect", "ClaudeSDKClient.connect"))
        targets.append((claude_agent_sdk, "query", "claude_agent_sdk.query"))
    except ImportError:
        pass
    try:
        from conductor.providers import claude_agent_sdk as provider_module

        provider = provider_module.ClaudeAgentSdkProvider
        for attr in ("execute", "validate_connection", "_check_auth_readiness"):
            targets.append((provider, attr, "ClaudeAgentSdkProvider." + attr))
        auth = "_run_auth_status_subprocess"
        targets.append((provider_module, auth, auth))
    except ImportError:
        pass
    for owner, attr, name in targets:
        _arm(owner, attr, name)


def pytest_sessionfinish(session, exitstatus):
    while _saved:
        owner, attr, original = _saved.pop()
        setattr(owner, attr, original)
'''

CONFTEST_TEMPLATE = """
import importlib.util
import os
import shutil
import sys

import pytest

_spec = importlib.util.spec_from_file_location("conductor_root_conftest_under_test", r"{root}")
_root = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_root)
pytest_collection_modifyitems = _root.pytest_collection_modifyitems
_isolate_event_log_root = _root._isolate_event_log_root
_isolate_run_records_root = _root._isolate_run_records_root
_isolated_runs_dir = _root._isolated_runs_dir
_stub_claude_auth_readiness = _root._stub_claude_auth_readiness
{extra}
"""

PRELUDE = """
import importlib.util
import sys

import pytest

_spec = importlib.util.spec_from_file_location("live_module_under_test", r"{live}")
lm = importlib.util.module_from_spec(_spec)
sys.modules["live_module_under_test"] = lm
_spec.loader.exec_module(lm)
for _name in {exports!r}:
    globals()[_name] = getattr(lm, _name)
"""

EXTRA_CLI_NONE = """
@pytest.fixture(autouse=True)
def _cli_none(monkeypatch):
    monkeypatch.setattr("conductor.providers.claude_agent_sdk._find_claude_cli", lambda: None)
"""

EXTRA_SDK_BLOCKED = """
@pytest.fixture(autouse=True)
def _sdk_blocked(monkeypatch):
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)
"""

EXTRA_PS_MISSING = """
@pytest.fixture(autouse=True)
def _ps_missing(monkeypatch):
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda name, *a, **k: None if name == "ps" else real_which(name, *a, **k)
    )
"""

EXTRA_FILE_CONSOLE = """
@pytest.fixture(autouse=True)
def _file_console_set(monkeypatch):
    monkeypatch.setattr("conductor.cli.run._file_console", object())
"""

# Before the first test item can reach preflight, the Class R builder replaces the module-level
# ``read_git_state`` on the module object whose globals the live test functions really use (the
# function's own ``__globals__``: not a second import of the module).  A real ``git`` subprocess is
# forbidden in every Class R run.
GIT_SEAM_CONFTEST = """
GIT_SEAM_CALLS = []


def pytest_collection_finish(session):
    import json as _json
    import os as _os

    pair = _json.loads(_os.environ.get("SANDBOX_GIT_PAIR", '["' + "0" * 40 + '", false]'))
    fail = bool(_os.environ.get("SANDBOX_GIT_FAIL"))
    for item in session.items:
        function = getattr(item, "function", None)
        namespace = getattr(function, "__globals__", None)
        if namespace is not None and "read_git_state" in namespace:
            def fake_git_state(config, tmp_path, *, run=None, _pair=pair, _ns=namespace):
                GIT_SEAM_CALLS.append("read_git_state")
                with open("git_seam_calls.txt", "a") as handle:
                    handle.write("read_git_state\\n")
                if fail:  # a Git failure the preflight reports as ``case_failed``
                    raise _ns["HarnessFailure"](_ns["Outcome"].CASE_FAILED, "git unavailable")
                return _pair[0], bool(_pair[1])

            namespace["read_git_state"] = fake_git_state
"""

LIVE_EXPORTS = tuple(lm.SANDBOX_EXPORTS)
LIVE_EXPORTS_NO_OVERRIDE = tuple(
    n for n in lm.SANDBOX_EXPORTS if n != "_stub_claude_auth_readiness"
)

SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
FORBIDDEN_SCRATCH_IMPORTS = ("conductor", "claude_agent_sdk", "tests")
FORBIDDEN_SCRATCH_TEXT = (
    "live_module_under_test",
    "test_claude_agent_sdk_subscription_real",
    "claude_agent_sdk",
    "from conductor",
    "import conductor",
)


def prelude(exports: Sequence[str] = LIVE_EXPORTS) -> str:
    return PRELUDE.format(live=str(LIVE_MODULE), exports=tuple(exports))


def scratch_import_problems(source: str) -> list[str]:
    """Imports (AST) and live-module references (text) that a Class S file must not contain."""
    problems: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None  # a deliberate syntax-error scenario: only the text check applies
    if tree is not None:
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for name in names:
                if name.split(".")[0] in FORBIDDEN_SCRATCH_IMPORTS:
                    problems.append(f"import {name}")
    problems.extend(f"text {t}" for t in FORBIDDEN_SCRATCH_TEXT if t in source)
    return problems


class Sandbox:
    """The one sandbox builder.  ``klass`` is ``"S"`` (scratch-only) or ``"R"`` (real code)."""

    def __init__(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, klass: str = "R"
    ) -> None:
        assert klass in ("S", "R")
        self.pytester = pytester
        self.monkeypatch = monkeypatch
        self.klass = klass
        self.last_argv: list[str] = []
        pytester.makepyfile(tripwires=LAYER1_PLUGIN)
        if klass == "R":
            pytester.makepyfile(seams=SEAM_PLUGIN)
        for sub in ("home", "xdg-config", "xdg-data", "xdg-cache", "tmp"):
            (pytester.path / "_sbx" / sub).mkdir(parents=True, exist_ok=True)

    # -- writing files -----------------------------------------------------------------------

    def conftest(self, extra: str = "", *, where: Path | None = None) -> None:
        assert self.klass == "R", "a Class S sandbox never loads the repository conftest"
        text = CONFTEST_TEMPLATE.format(root=str(ROOT_CONFTEST), extra=extra + GIT_SEAM_CONFTEST)
        target = (where or self.pytester.path) / "conftest.py"
        target.write_text(text)

    def write(self, relpath: str, source: str) -> Path:
        if self.klass == "S":
            assert scratch_import_problems(source) == [], relpath
        target = self.pytester.path / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        return target

    def live_tests(self, relpath: str = "test_live_sandbox.py", *, override: bool = True) -> Path:
        assert self.klass == "R", "only a Class R sandbox collects the real live tests"
        exports = LIVE_EXPORTS if override else LIVE_EXPORTS_NO_OVERRIDE
        return self.write(relpath, prelude(exports))

    # -- the constructed environment (S9) ----------------------------------------------------

    def child_environment(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        """The environment of the child: constructed, never filtered from the parent's."""
        root = self.pytester.path / "_sbx"
        env = {
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "TEMP": str(root / "tmp"),
            "TMP": str(root / "tmp"),
            "XDG_CONFIG_HOME": str(root / "xdg-config"),
            "XDG_DATA_HOME": str(root / "xdg-data"),
            "XDG_CACHE_HOME": str(root / "xdg-cache"),
            "PATH": SYSTEM_PATH,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if self.klass == "R":
            env["PYTHONPATH"] = str(REPO_ROOT / "src")
        self.assert_isolated(env)  # the constructed base: no declared extra is in it yet
        for key, value in (extra or {}).items():  # a control's own declared variables only (S8)
            env[key] = value
        return env

    def assert_isolated(self, env: Mapping[str, str]) -> None:
        """Fail closed before pytest runs unless the S9 rules hold."""
        root = self.pytester.path.resolve()
        assert shutil.which("claude", path=SYSTEM_PATH) is None
        assert shutil.which("claude.exe", path=SYSTEM_PATH) is None
        for name in env:
            assert not name.startswith(("ANTHROPIC_", "CLAUDE_")), name
        for name in ("HOME", "TMPDIR", "TEMP", "TMP", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
            assert Path(env[name]).resolve().is_relative_to(root), name
        assert Path(env["XDG_CACHE_HOME"]).resolve().is_relative_to(root)
        for name, value in env.items():
            if name in ("PATH", "PYTHONPATH") or not value.startswith("/"):
                continue
            if name.startswith("TRIPWIRE"):
                continue
            assert Path(value).resolve().is_relative_to(root), name

    # -- running -----------------------------------------------------------------------------

    def run(
        self,
        *args: str,
        gate: bool = True,
        env: Mapping[str, str] | None = None,
        expect_hits: bool = False,
    ) -> pytest.RunResult:
        extra = dict(env or {})
        if gate:
            extra[lm.GATE_ENV] = "1"
        child = self.child_environment(extra)
        plugins = ["-p", "tripwires"] + (["-p", "seams"] if self.klass == "R" else [])
        self.last_argv = [*plugins, "-p", "no:cacheprovider", *args]
        saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(child)
        try:
            result = self.pytester.runpytest_subprocess(*self.last_argv)
        finally:
            os.environ.clear()
            os.environ.update(saved)
        self.assert_clean_run(expect_hits=expect_hits)
        return result

    def assert_clean_run(self, *, expect_hits: bool = False) -> None:
        """Zero tripwire hits (inverted only for a positive control) and the S2 import audit."""
        if not expect_hits:
            assert self.hits() == [], "a tripwire was hit"
        if self.klass == "S":
            audit = self.pytester.path / "modules_audit.txt"
            if audit.exists():
                assert audit.read_text().split() == [], "a live module was imported in Class S"

    def hits(self) -> list[str]:
        path = self.pytester.path / "tripwire_hits.txt"
        return path.read_text().split() if path.exists() else []


@pytest.fixture
def sandbox(pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch) -> Sandbox:
    """A Class R sandbox: real code under test over fakes."""
    return Sandbox(pytester, monkeypatch, "R")


@pytest.fixture
def scratch(pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch) -> Sandbox:
    """A Class S sandbox: scratch-only."""
    return Sandbox(pytester, monkeypatch, "S")


# ============================================================================
# Tripwire positive controls
# ============================================================================

LAYER1_CONTROL = """
import asyncio
import os
import socket
import subprocess

import pytest

pytestmark = pytest.mark.real_api


def _hit(fn, *args, **kwargs):
    try:
        result = fn(*args, **kwargs)
        if asyncio.iscoroutine(result):
            result.close()
    except AssertionError as exc:
        assert "tripwire" in str(exc)
        return
    raise RuntimeError("tripwire not armed")


def test_every_layer1_family_is_armed():
    _hit(subprocess.Popen, ["x"])
    _hit(os.posix_spawn, "x", ["x"], {})
    _hit(os.posix_spawnp, "x", ["x"], {})
    for name in ("execv", "execve", "execvp", "execvpe"):
        _hit(getattr(os, name), "x", ["x"], *([{}] if name.endswith("e") else []))
    for name in ("execl", "execle", "execlp", "execlpe"):
        _hit(getattr(os, name), "x", "x", *([{}] if name.endswith("e") else []))
    _hit(os.system, "x")
    _hit(os.popen, "x")
    _hit(asyncio.create_subprocess_exec, "x")
    _hit(asyncio.create_subprocess_shell, "x")
    loop = asyncio.new_event_loop()
    _hit(loop.subprocess_exec, None, "x")
    _hit(loop.subprocess_shell, None, "x")
    loop.close()
    _hit(socket.socket().connect, ("127.0.0.1", 9))
    _hit(socket.socket().connect_ex, ("127.0.0.1", 9))
    _hit(socket.create_connection, ("127.0.0.1", 9))
    _hit(socket.getaddrinfo, "example.invalid", 80)
"""

SEAM_CONTROL = """
import asyncio

import pytest


def _hit(fn, *args):
    try:
        result = fn(*args)
        if asyncio.iscoroutine(result):
            result.close()
    except AssertionError as exc:
        assert "tripwire" in str(exc)
        return
    raise RuntimeError("tripwire not armed")


def test_every_seam_is_armed():
    import anyio
    import claude_agent_sdk
    from conductor.providers import claude_agent_sdk as provider_module

    provider = provider_module.ClaudeAgentSdkProvider
    _hit(anyio.open_process, ["x"])
    _hit(claude_agent_sdk.ClaudeSDKClient.connect, None)
    _hit(claude_agent_sdk.query)
    _hit(provider.execute, None)
    _hit(provider.validate_connection, None)
    _hit(provider._check_auth_readiness, None)
    _hit(provider_module._run_auth_status_subprocess)
"""


def test_layer1_tripwires_are_armed_positive_control(scratch: Sandbox) -> None:
    """Every Layer-1 family raises and records exactly its own fixed identifier."""
    scratch.pytester.makeini(SANDBOX_INI)
    scratch.write("test_control.py", LAYER1_CONTROL)
    result = scratch.run("test_control.py", "-m", "real_api", gate=False, expect_hits=True)
    result.assert_outcomes(passed=1)
    assert set(scratch.hits()) == set(LAYER1_NAMES)
    assert len(scratch.hits()) == len(LAYER1_NAMES)  # exactly one hit per call, no extras


def test_layer2_seam_recorders_are_armed_positive_control(sandbox: Sandbox) -> None:
    pytest.importorskip("claude_agent_sdk")
    pytest.importorskip("anyio")
    sandbox.write("test_control.py", SEAM_CONTROL)
    result = sandbox.run("test_control.py", gate=False, expect_hits=True)
    result.assert_outcomes(passed=1)
    assert set(sandbox.hits()) == set(SEAM_NAMES)


# ============================================================================
# H1-H5e, H7, H8 (sandbox): gates
# ============================================================================


class TestSandboxGates:
    def test_h1_neither_gate(self, sandbox: Sandbox) -> None:
        sandbox.conftest()
        sandbox.live_tests()
        result = sandbox.run("test_live_sandbox.py", "-rs", gate=False)
        result.assert_outcomes(skipped=2)
        assert result.ret == 0
        assert sandbox.hits() == []

    def test_h2_ci_expression_deselects(self, sandbox: Sandbox) -> None:
        sandbox.conftest()
        sandbox.live_tests()
        result = sandbox.run(
            "test_live_sandbox.py",
            "-m",
            "not real_api and not install_scripts and not performance",
            gate=False,
            env={"ANTHROPIC_API_KEY": "sk-ant-test-fake-key-for-mocking"},
        )
        result.assert_outcomes(deselected=2)
        assert sandbox.hits() == []

    def test_h3_marker_only(self, sandbox: Sandbox) -> None:
        sandbox.conftest()
        sandbox.live_tests()
        for env in ({}, {"ANTHROPIC_API_KEY": "sk-ant-test-fake-key-for-mocking"}):
            result = sandbox.run(
                "test_live_sandbox.py", "-m", "real_api", "-rs", gate=False, env=env
            )
            result.assert_outcomes(skipped=2)
            assert lm.GATE_ENV in result.stdout.str()
            assert sandbox.hits() == []

    def test_h4_env_only_hook_skips(self, sandbox: Sandbox) -> None:
        sandbox.conftest()
        sandbox.live_tests()
        result = sandbox.run("test_live_sandbox.py", "-rs")
        result.assert_outcomes(skipped=2)
        assert "opt in with -m real_api" in result.stdout.str()
        assert sandbox.hits() == []

    def test_h5e_env_only_noconftest(self, sandbox: Sandbox) -> None:
        sandbox.live_tests()
        result = sandbox.run("test_live_sandbox.py", "--noconftest")
        result.assert_outcomes(failed=2)
        assert "LiveOptInError" in result.stdout.str()
        assert sandbox.hits() == []

    def test_h7_xdist_worker(self, sandbox: Sandbox) -> None:
        sandbox.conftest()
        sandbox.live_tests()
        result = sandbox.run(
            "test_live_sandbox.py", "-m", "real_api", env={"PYTEST_XDIST_WORKER": "gw0"}
        )
        result.assert_outcomes(failed=2)
        assert "LiveOptInError" in result.stdout.str()
        assert sandbox.hits() == []

    def test_h8_marker_expression_sandbox_pair(self, sandbox: Sandbox) -> None:
        sandbox.conftest(EXTRA_CLI_NONE)
        sandbox.live_tests()
        # ``not real_api``: pytest deselects the live tests, so they can never run.
        result = sandbox.run("test_live_sandbox.py", "-m", "not real_api")
        result.assert_outcomes(deselected=2)
        assert sandbox.hits() == []
        # ``real_api or not real_api`` mentions and selects the marker: the guard accepts.
        result = sandbox.run("test_live_sandbox.py", "-m", "real_api or not real_api")
        result.assert_outcomes(failed=2)
        assert "prereq_cli_missing" in result.stdout.str()
        assert sandbox.hits() == []


# ============================================================================
# H5a-H5d (sandbox): isolation prerequisite
# ============================================================================


class TestSandboxIsolation:
    def test_h5a_noconftest(self, sandbox: Sandbox) -> None:
        sandbox.conftest()
        sandbox.live_tests()
        result = sandbox.run("test_live_sandbox.py", "-m", "real_api", "--noconftest", "-rs")
        result.assert_outcomes(failed=2)
        out = result.stdout.str()
        assert "isolation_fixtures_missing" in out
        assert "skipped" not in result.parseoutcomes()
        assert sandbox.hits() == []

    def test_h5b_confcutdir(self, sandbox: Sandbox) -> None:
        sandbox.conftest()  # sits above --confcutdir, so it is never loaded
        sub = sandbox.pytester.path / "sub"
        sandbox.live_tests("sub/test_live_sandbox.py")
        result = sandbox.run("-m", "real_api", f"--confcutdir={sub}", "sub")
        result.assert_outcomes(failed=2)
        assert "isolation_fixtures_missing" in result.stdout.str()
        assert sandbox.hits() == []

    def test_h5c_other_rootdir(
        self, sandbox: Sandbox, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        other = tmp_path_factory.mktemp("other-root")
        (other / "test_live_sandbox.py").write_text(prelude())
        result = sandbox.run("-m", "real_api", f"--rootdir={other}", str(other))
        result.assert_outcomes(failed=2)
        assert "isolation_fixtures_missing" in result.stdout.str()
        assert sandbox.hits() == []

    def test_h5d_isolation_passes_cli_missing(self, sandbox: Sandbox) -> None:
        sandbox.conftest(EXTRA_CLI_NONE)
        sandbox.live_tests()
        result = sandbox.run("test_live_sandbox.py", "-m", "real_api")
        result.assert_outcomes(failed=2)
        out = result.stdout.str()
        assert "prereq_cli_missing" in out
        assert "isolation_fixtures_missing" not in out
        assert sandbox.hits() == []


# ============================================================================
# H6, H9, H17 (sandbox): prerequisites, readiness stub, _file_console
# ============================================================================


class TestSandboxPrerequisites:
    @pytest.mark.parametrize(
        ("extra", "enum"),
        [
            (EXTRA_CLI_NONE, "prereq_cli_missing"),
            (EXTRA_SDK_BLOCKED, "prereq_sdk_missing"),
            (EXTRA_PS_MISSING, "prereq_ps_missing"),
        ],
        ids=["cli", "sdk", "ps"],
    )
    def test_h6_prerequisite_fails_closed(self, sandbox: Sandbox, extra: str, enum: str) -> None:
        sandbox.conftest(extra)
        sandbox.live_tests()
        result = sandbox.run("test_live_sandbox.py", "-m", "real_api", "-rs")
        result.assert_outcomes(failed=2)  # failed, never skipped
        assert enum in result.stdout.str()
        assert sandbox.hits() == []

    def test_h9_readiness_stub_overridden(self, sandbox: Sandbox) -> None:
        sandbox.conftest()
        body = (
            prelude(("_stub_claude_auth_readiness",))
            + "\n\ndef test_real_readiness():\n    lm.assert_real_readiness()\n"
        )
        sandbox.write("test_h9_with_override.py", body)
        result = sandbox.run("test_h9_with_override.py", "-k", "test_real_readiness", gate=False)
        result.assert_outcomes(passed=1)
        assert sandbox.hits() == []

    def test_h9_readiness_stub_active_without_override(self, sandbox: Sandbox) -> None:
        sandbox.conftest()
        body = prelude(()) + (
            "\n\ndef test_stub_detected():\n"
            "    with pytest.raises(lm.HarnessFailure) as info:\n"
            "        lm.assert_real_readiness()\n"
            "    assert info.value.outcome == lm.Outcome.READINESS_STUB_ACTIVE\n"
        )
        sandbox.write("test_h9_without_override.py", body)
        result = sandbox.run("test_h9_without_override.py", "-k", "test_stub_detected", gate=False)
        result.assert_outcomes(passed=1)
        assert sandbox.hits() == []

    def test_h17_file_console_preflight(self, sandbox: Sandbox) -> None:
        sandbox.conftest(EXTRA_FILE_CONSOLE)
        sandbox.live_tests()
        result = sandbox.run("test_live_sandbox.py", "-m", "real_api")
        result.assert_outcomes(failed=2)
        out = result.stdout.str()
        assert "prereq_file_console_active" in out
        assert "not_executed_after_safety_failure" in out
        assert '"case"' not in out  # no L0/L1/L3/L2 evidence record was produced
        # Path A: exactly one run-level record (the second test's hand-over is refused), never
        # duplicated by ``fail_closed``, with the session prefix and every case not executed
        (record,) = evidence_records(out)
        assert record["primary_failure"] == "session:prereq_file_console_active:HarnessFailure"
        assert record["not_executed"] == (
            "L0:not_executed_after_safety_failure,L1:not_executed_after_safety_failure,"
            "L3:not_executed_after_safety_failure,L2:not_executed_after_safety_failure"
        )
        assert sandbox.hits() == []  # readiness never called; no CLI/SDK/process/network entry

    def test_live_tests_build_real_adapters_and_fail_closed_on_prerequisite(
        self, sandbox: Sandbox
    ) -> None:
        """Both live tests resolve their fixtures (capfd without capsys), construct the real
        adapter set, and stop at the preflight: no case, no adapter entry point, no hit."""
        pytest.importorskip("claude_agent_sdk")
        sandbox.conftest(EXTRA_CLI_NONE)
        sandbox.live_tests()
        result = sandbox.run("test_live_sandbox.py", "-m", "real_api")
        result.assert_outcomes(failed=2)
        out = result.stdout.str()
        assert "prereq_cli_missing" in out
        assert "cannot use" not in out  # no capture-fixture conflict at setup
        assert "adapters_not_wired" not in out
        assert '"case"' not in out
        assert "skipped_reports: 0" in out
        assert sandbox.hits() == []


# ============================================================================
# H10 (sandbox): session-wide zero-skip plugin
# ============================================================================

ZERO_SKIP_EXPORT = ("_register_zero_skip_reporter",)
ALL_MARKERS = ("-m", "real_api or not real_api")


class TestZeroSkipSandbox:
    def _skip_file(self, sandbox: Sandbox, name: str, *, with_fixture: bool, body: str) -> None:
        head = prelude(ZERO_SKIP_EXPORT) if with_fixture else "import pytest\n"
        sandbox.write(name, head + "\n\n" + body)

    def test_h10_i_skip_in_passing_session_fails_it(self, sandbox: Sandbox) -> None:
        self._skip_file(
            sandbox,
            "test_z.py",
            with_fixture=True,
            body="def test_ok():\n    assert True\n\n"
            "def test_skips():\n    pytest.skip('unexpected skip')\n",
        )
        result = sandbox.run("test_z.py", *ALL_MARKERS)
        result.assert_outcomes(passed=1, skipped=1)
        assert result.ret == 1
        out = result.stdout.str()
        assert "skipped_reports: 1" in out
        assert "zero_skip_verdict: fail" in out
        assert "official: false" in out
        assert sandbox.hits() == []

    def test_h10_ii_failing_primary_is_preserved(self, sandbox: Sandbox) -> None:
        self._skip_file(
            sandbox,
            "test_z.py",
            with_fixture=True,
            body="def test_primary(pytestconfig):\n"
            "    lm.fail_closed(lm.HarnessFailure(lm.Outcome.CASE_FAILED), pytestconfig)\n\n"
            "def test_skips():\n    pytest.skip('unexpected skip')\n",
        )
        result = sandbox.run("test_z.py", *ALL_MARKERS)
        result.assert_outcomes(failed=1, skipped=1)
        out = result.stdout.str()
        assert result.ret == 1  # still the primary failing status, neither lowered nor replaced
        assert "case_failed:HarnessFailure" in out  # the fixed form of the primary failure
        assert "skipped_reports: 1" in out

    def test_h10_iii_gates_inactive_plugin_not_registered(self, sandbox: Sandbox) -> None:
        self._skip_file(
            sandbox,
            "test_z.py",
            with_fixture=True,
            body="def test_skips():\n    pytest.skip('a skip')\n",
        )
        result = sandbox.run("test_z.py", *ALL_MARKERS, gate=False)
        result.assert_outcomes(skipped=1)
        assert result.ret == 0
        assert "claude subscription live evidence" not in result.stdout.str()

    def test_h10_iv_dash_p_no_terminal_without_the_exact_flags(self, sandbox: Sandbox) -> None:
        """``-p no:terminal`` with ordinary flags reaches the fixture branch.  Under the exact flags
        it is a usage error instead (``TestRegistrationBoundaries``), so it is never the test of
        this enum there; the scratch plugin that unregisters the reporter is."""
        self._skip_file(
            sandbox,
            "test_z.py",
            with_fixture=True,
            body="def test_ok():\n    assert True\n",
        )
        result = sandbox.run("test_z.py", *ALL_MARKERS, "-p", "no:terminal", "--junitxml=out.xml")
        assert result.ret != 0
        assert "prereq_terminalreporter_missing" in (sandbox.pytester.path / "out.xml").read_text()
        assert sandbox.hits() == []

    def test_h10_v_reports_before_and_after_registration_counted_once(
        self, sandbox: Sandbox
    ) -> None:
        self._skip_file(
            sandbox,
            "test_a_first.py",
            with_fixture=False,
            body="def test_skip_before_registration():\n    pytest.skip('before')\n",
        )
        self._skip_file(
            sandbox,
            "test_b_second.py",
            with_fixture=True,
            body="def test_skip_after_registration():\n    pytest.skip('after')\n",
        )
        result = sandbox.run("test_a_first.py", "test_b_second.py", *ALL_MARKERS)
        result.assert_outcomes(skipped=2)
        assert result.ret == 1
        assert "skipped_reports: 2" in result.stdout.str()

    def test_h10_vi_xfail_is_not_a_skip(self, sandbox: Sandbox) -> None:
        xfail = (
            "@pytest.mark.xfail(reason='expected')\n"
            "def test_expected_failure():\n    assert False\n\n"
            "@pytest.mark.xfail(run=False, reason='expected')\n"
            "def test_expected_not_run():\n    assert False\n\n"
        )
        self._skip_file(
            sandbox,
            "test_a_first.py",
            with_fixture=False,
            body=xfail.replace("def test_", "def test_pre_"),
        )
        self._skip_file(sandbox, "test_b_second.py", with_fixture=True, body=xfail)
        result = sandbox.run("test_a_first.py", "test_b_second.py", *ALL_MARKERS)
        assert result.ret == 0
        out = result.stdout.str()
        assert "skipped_reports: 0" in out
        assert "zero_skip_verdict: pass" in out
        # With one real skip added alongside, the count is exactly 1 and the session fails.
        self._skip_file(
            sandbox,
            "test_c_third.py",
            with_fixture=False,
            body="def test_real_skip():\n    pytest.skip('real')\n",
        )
        result = sandbox.run("test_a_first.py", "test_b_second.py", "test_c_third.py", *ALL_MARKERS)
        assert result.ret == 1
        assert "skipped_reports: 1" in result.stdout.str()


# ============================================================================
# H21, H27-H31 (sandbox): private logs, the report sanitizer and the exact command output
# ============================================================================

SECRET = "SECRET-LIKE-DEBUG-LINE-9137"
PARTS = ("msg", "ctx", "cause", "src", "repr")


def plant(name: str, part: str) -> str:
    """A unique secret for one scenario (the sandbox module builds the same strings)."""
    return f"PLANTED-{name}-{part}-4417"


# A sandbox test module that behaves like a live case on the output surface.  Every scenario
# writes a secret-like DEBUG record on a private logger and raw text to fd 1 / fd 2 / ``print``
# inside the real ``PrivateLogCapture``, emits one real evidence record through the real
# terminal-summary hook, and then passes, fails, times out or is interrupted.  Each failing
# scenario plants distinct secrets where pytest would render them: the message, ``__context__``,
# ``__cause__``, a fixture repr, a source line and an absolute path.
SURFACE_BODY = """

import asyncio
import logging
import os
import sys
import warnings
from pathlib import Path

pytestmark = pytest.mark.real_api
SECRET = "SECRET-LIKE-DEBUG-LINE-9137"
CANARY = lm.make_canary()


def plant(name, part):
    return "PLANTED-" + name + "-" + part + "-4417"


class Leaky:
    def __repr__(self):
        return "LEAKY-FIXTURE-" + plant("fixture_repr", "repr")


@pytest.fixture
def leaky():
    return Leaky()


def _noisy():
    with lm.PrivateLogCapture(CANARY) as logs:
        logger = logging.getLogger("claude_agent_sdk._internal.transport.subprocess_cli")
        logger.debug("Skipping non-JSON line from CLI stdout: %s", SECRET)
        logging.getLogger("conductor.providers.claude_agent_sdk").debug("provider %s", SECRET)
        os.write(1, ("STDOUT " + SECRET + "\\n").encode())
        os.write(2, ("STDERR " + SECRET + "\\n").encode())
        print("PRINT " + SECRET)
        assert SECRET in logs.text  # captured privately, and only there


def _emit(config, outcome=lm.Outcome.OK, interrupted="none"):
    emit = lm._default_emit(config)
    emit(
        lm.evidence(
            case="L0",
            outcome=outcome,
            adapter_outcome=outcome,
            secondary_findings=[],
            interrupted=interrupted,
            descendants="no_descendants_remaining",
            canary_scan=list(lm.EMPTY_SCAN),
        )
    )
    run = {"quota_attempts_total": 0, "quota_ceiling": 3}
    if outcome is not lm.Outcome.OK:
        cls = {"keyboard_interrupt": "KeyboardInterrupt", "cancelled": "CancelledError"}
        who = cls.get(interrupted, "HarnessFailure")
        run["primary_failure"] = "L0:" + outcome.value + ":" + who
    emit(lm.evidence(**run))  # the one run-level record (Path A); a later fail_closed adds none


@pytest.fixture
def broken_setup(pytestconfig):
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    raise RuntimeError(plant("setup_error", "msg"))


@pytest.fixture
def broken_teardown(pytestconfig):
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    yield
    raise RuntimeError(plant("teardown_error", "msg"))


def test_pass(pytestconfig):
    _noisy()
    _emit(pytestconfig)


def test_harness_failure(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    lm.fail_closed(lm.HarnessFailure(lm.Outcome.CASE_FAILED), pytestconfig)


def test_aggregate_failure(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    first = lm.CaseResult(lm.Case.L0, "ok", lm.Outcome.OK)
    leak = (lm.Outcome.DESCENDANT_LEAK,)
    second = lm.CaseResult(lm.Case.L1, "failed", lm.Outcome.CASE_FAILED, "HarnessFailure", leak)
    lm.finalize(lm.SessionResult((lm.Case.L0, lm.Case.L1), [first, second], 1, 3, []))


def test_chained_provider_failure(pytestconfig):
    # The live tests call ``fail_closed`` inside ``except HarnessFailure``; the wrapped
    # exception's own text must not be printed either.
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    try:
        try:
            raise RuntimeError("CHAINED " + plant("chained_provider_failure", "msg"))
        except RuntimeError as inner:
            raise lm.HarnessFailure(lm.Outcome.ADAPTERS_NOT_WIRED) from inner
    except lm.HarnessFailure as failure:
        lm.fail_closed(failure, pytestconfig)


def test_unexpected_exception(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    raise OSError(plant("unexpected_exception", "msg"))


def test_exception_message(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    raise RuntimeError("provider said " + plant("exception_message", "msg"))


def test_context(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    try:
        raise RuntimeError(plant("context", "ctx"))
    except RuntimeError:
        raise ValueError(plant("context", "msg"))


def test_cause(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    raise ValueError(plant("cause", "msg")) from RuntimeError(plant("cause", "cause"))


def test_fixture_repr(pytestconfig, leaky):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    raise RuntimeError("no secret in the message")


def test_tmp_path_repr(pytestconfig, tmp_path):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    raise RuntimeError("no secret in the message")


def test_source_line(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    expected = "OK"
    assert expected == "PLANTED-source_line-src-4417"


def test_absolute_path(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.CASE_FAILED)
    where = "/Users/planted/.claude/" + plant("absolute_path", "msg")
    raise FileNotFoundError(2, "No such file", where)


def test_warning(pytestconfig):
    _noisy()
    warnings.simplefilter("always")
    text = "provider said " + plant("warning", "msg") + " in /Users/planted/.claude/x.py"
    warnings.warn(text, DeprecationWarning)
    warnings.warn("unclosed " + plant("warning", "cause"), ResourceWarning)
    warnings.warn("user " + plant("warning", "ctx"), UserWarning)
    _emit(pytestconfig)


def test_stdout_stderr(pytestconfig):
    _noisy()
    sys.stdout.write(plant("stdout_stderr", "msg") + "\\n")
    sys.stderr.write(plant("stdout_stderr", "ctx") + "\\n")
    os.write(1, (plant("stdout_stderr", "cause") + "\\n").encode())
    os.write(2, (plant("stdout_stderr", "src") + "\\n").encode())
    _emit(pytestconfig)


def test_private_debug(pytestconfig):
    _noisy()
    with lm.PrivateLogCapture(CANARY) as logs:
        logging.getLogger("claude_agent_sdk").debug("%s", plant("private_debug", "msg"))
        assert plant("private_debug", "msg") in logs.text
    _emit(pytestconfig)


def test_timeout(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.INCONCLUSIVE)
    try:
        asyncio.run(asyncio.wait_for(asyncio.sleep(30), 0.05))
    except TimeoutError:
        lm.fail_closed(lm.HarnessFailure(lm.Outcome.INCONCLUSIVE), pytestconfig)


def test_cancelled_error(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.INTERRUPTED, "cancelled")
    raise asyncio.CancelledError(plant("cancelled_error", "msg"))


def test_cancelled_error_chained(pytestconfig, leaky):
    _noisy()
    _emit(pytestconfig, lm.Outcome.INTERRUPTED, "cancelled")
    try:
        raise RuntimeError(plant("cancelled_error_chained", "ctx"))
    except RuntimeError:
        raise asyncio.CancelledError(plant("cancelled_error_chained", "msg")) from ValueError(
            plant("cancelled_error_chained", "cause")
        )


def test_keyboard_interrupt(pytestconfig):
    _noisy()
    _emit(pytestconfig, lm.Outcome.INTERRUPTED, "keyboard_interrupt")
    raise KeyboardInterrupt(plant("keyboard_interrupt", "msg"))


def test_keyboard_interrupt_chained(pytestconfig, leaky):
    _noisy()
    _emit(pytestconfig, lm.Outcome.INTERRUPTED, "keyboard_interrupt")
    try:
        raise RuntimeError(plant("keyboard_interrupt_chained", "ctx"))
    except RuntimeError:
        raise KeyboardInterrupt(plant("keyboard_interrupt_chained", "msg")) from ValueError(
            plant("keyboard_interrupt_chained", "cause")
        )


def test_setup_error(broken_setup):
    pass


def test_teardown_error(broken_teardown):
    pass
"""

# scenario -> (exit status through ``pipefail``, the fixed text the failure renders as)
UNEXPECTED = "unexpected exception"
SCENARIOS: dict[str, tuple[int, str | None]] = {
    "test_pass": (0, None),
    "test_harness_failure": (1, "case_failed:HarnessFailure"),
    "test_aggregate_failure": (
        1,
        "cases: L0:ok,L1:case_failed; first_failure: L1:case_failed:HarnessFailure; "
        "also: L1:descendant_leak",
    ),
    "test_chained_provider_failure": (1, "adapters_not_wired:HarnessFailure"),
    "test_unexpected_exception": (1, f"{UNEXPECTED}: OSError"),
    "test_exception_message": (1, f"{UNEXPECTED}: RuntimeError"),
    "test_context": (1, f"{UNEXPECTED}: ValueError"),
    "test_cause": (1, f"{UNEXPECTED}: ValueError"),
    "test_fixture_repr": (1, f"{UNEXPECTED}: RuntimeError"),
    "test_tmp_path_repr": (1, f"{UNEXPECTED}: RuntimeError"),
    "test_source_line": (1, f"{UNEXPECTED}: AssertionError"),
    "test_absolute_path": (1, f"{UNEXPECTED}: FileNotFoundError"),
    "test_warning": (0, None),
    "test_stdout_stderr": (0, None),
    "test_private_debug": (0, None),
    "test_timeout": (1, "inconclusive:HarnessFailure"),
    "test_cancelled_error": (1, f"{UNEXPECTED}: CancelledError"),
    "test_cancelled_error_chained": (1, f"{UNEXPECTED}: CancelledError"),
    "test_keyboard_interrupt": (2, None),
    "test_keyboard_interrupt_chained": (2, None),
    "test_setup_error": (1, f"{UNEXPECTED}: RuntimeError"),
    "test_teardown_error": (1, f"{UNEXPECTED}: RuntimeError"),
}

# What may reach a saved capture is the closed grammar of the live module's classifier: there is
# no traceback, source, locals, fixture, location, ``FAILURES``/``ERRORS``/short-summary or
# ``FAILED``/``ERROR`` line, and no per-test or per-exception allowance.  A line is a form of the
# grammar or a validated ``EVIDENCE`` record.
LOCAL_PATH_MARKERS = (
    "/Users/",
    "/home/",
    "/private/",
    "/tmp/",
    "/var/",
    "pytest-of-",
    "site-packages",
)


def output_problems(text: str) -> list[str]:
    """Lines of ``text`` outside the closed grammar, and invalid ``EVIDENCE`` records."""
    problems: list[str] = []
    for line in text.splitlines():
        form = lm._form_of(line)
        if form is None:
            problems.append(f"unvetted line: {line[:80]}")
        elif form == "G5":
            try:
                lm.emit_evidence(json.loads(line[len("EVIDENCE ") :]))
            except (ValueError, lm.EvidenceError):
                problems.append(f"invalid evidence line: {line[:60]}")
    return problems


def local_path_problems(text: str, *extra: object) -> list[str]:
    """Every absolute local path (and the given sandbox, repository or home path) in ``text``."""
    markers = [*LOCAL_PATH_MARKERS, *(str(e) for e in extra), str(Path.home()), str(REPO_ROOT)]
    return [m for m in markers if m and m in text]


def authorized_flags(command: str) -> list[str]:
    """The pytest flags of an authorized command, exactly as the live module defines them."""
    tokens = shlex.split(command.replace("\\\n", " "))
    start = tokens.index(
        "-m", tokens.index("pytest") + 1
    )  # the ``-m real_api`` after ``-m pytest``
    end = tokens.index("2>&1") if "2>&1" in tokens else len(tokens)
    flags = tokens[start:end]
    flags.remove(lm._TEST_MODULE)  # the sandbox names its own module
    del flags[flags.index("-k") : flags.index("-k") + 2]  # ... and selects a test by node id
    return flags


# The old, unsafe surface: the root logger raised to DEBUG feeds pytest's report handler and
# ``-rA`` prints the "Captured log" section of a passing test.
CONTROL_BODY = """

import logging

pytestmark = pytest.mark.real_api
SECRET = "SECRET-LIKE-DEBUG-LINE-9137"


def test_old_surface(caplog):
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("claude_agent_sdk").debug("Skipping non-JSON line: %s", SECRET)
"""

BASH = shutil.which("bash")
ZSH = shutil.which("zsh")
needs_bash = pytest.mark.skipif(
    BASH is None or sys.platform == "win32", reason="the exact command needs bash (POSIX)"
)

# Every run of an exact-command sandbox logs each report as pytest finally sees it (after the
# sanitizer): this is how a test reads the rendering that ``--tb=no -rN`` keeps off the terminal.
REPORT_LOG_PLUGIN = """
import json as _rl_json


class _ReportLog:
    def pytest_runtest_logreport(self, report):
        longrepr = report.longrepr
        if not isinstance(longrepr, str) and hasattr(longrepr, "reprtraceback"):
            # an unsanitized pytest report: the lines of its last entry (the fixed fail text)
            entries = longrepr.reprtraceback.reprentries
            longrepr = "\\n".join(entries[-1].lines) if entries else ""
        elif not isinstance(longrepr, str):
            longrepr = repr(longrepr)
        with open("report_log.jsonl", "a") as handle:
            row = {"nodeid": report.nodeid, "when": report.when, "outcome": report.outcome}
            handle.write(_rl_json.dumps({**row, "longrepr": longrepr if report.failed else None}))
            handle.write("\\n")


def pytest_configure(config):
    config.pluginmanager.register(_ReportLog(), "sandbox-report-log")
"""


@dataclasses.dataclass(frozen=True)
class Ran:
    """One run of the exact authorized command structure in a bash subprocess."""

    returncode: int
    saved: str  # what ``tee`` wrote to the evidence file
    shown: str  # what the shell printed (``tee`` copies its input)
    stderr: str
    reports: tuple[dict[str, Any], ...] = ()
    argv_differences: tuple[tuple[str, str], ...] = ()
    control: bool = False  # a positive control: its capture was deleted and is never evidence

    def rendered(self, node: str, when: str = "call") -> str | None:
        """The ``longrepr`` text pytest finally held for ``node`` in phase ``when``."""
        for row in self.reports:
            if row["nodeid"].endswith(node.split("::")[-1]) and row["when"] == when:
                return row["longrepr"]
        raise AssertionError(f"no report for {node} in {when}")

    @property
    def verdict(self) -> tuple[str, str]:
        """The closed-grammar classifier's verdict for this capture and pipeline status."""
        assert not self.control, "a positive control is never classified as candidate evidence"
        return lm.classify_capture(self.saved, self.returncode)


# A scratch plugin that writes the evidence section from stored data lines, exactly like the real
# evidence plugin does (heading, the three G4 lines, then the records): Class S replays failure- or
# readiness-shaped data through the exact pipeline without importing any live code.
REPLAY_PLUGIN = """
import json
import os


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    path = os.path.join(os.getcwd(), "replay_data.json")
    if not os.path.exists(path):
        return
    with open(path) as handle:
        data = json.load(handle)
    terminalreporter.section("claude subscription live evidence")
    for line in data["g4"]:
        terminalreporter.write_line(line)
    for line in data["records"]:
        terminalreporter.write_line(line)
"""


def replay_data(parts: Mapping[str, Any]) -> str:
    """The G4 lines and record lines of a fabricated capture, as the replay plugin's data."""
    skipped, verdict, official = parts["g4"]
    records = []
    if parts["session"] is not None:
        records.append(rec(**parts["session"]))
    records += [rec(**c) for c in parts["cases"]]
    if parts["run"] is not None:
        records.append(rec(**parts["run"]))
    return json.dumps(
        {
            "g4": [
                f"skipped_reports: {skipped}",
                f"zero_skip_verdict: {verdict}",
                f"official: {official}",
            ],
            "records": records,
        }
    )


def token_delta(old: str, new: str) -> tuple[Counter[str], Counter[str]]:
    """``(removed, added)`` tokens going from ``old`` to ``new`` (both shell words)."""
    before, after = Counter(shlex.split(old)), Counter(shlex.split(new))
    return before - after, after - before


class Exact:
    """Runs the module's real command constant under ``bash``, ``pipefail`` and ``tee``.

    The calling environment is the sandbox's constructed one (S9) plus ``PY``, ``SRC`` and
    ``EVIDENCE_FILE``.  The builder diffs the sandbox argv against the constant and fails unless the
    differences are exactly the declared closed set of S8: the ``PYTHONPATH`` value, the module (a
    scratch node id), the ``-k`` value, the Layer-1 tripwire as the first ``-p`` argument, the
    Layer-2 seam recorders in Class R, any further declared scratch plugin and, for a negative
    control, exactly the tokens it declares as dropped or replaced.  The evidence file lives
    outside the sandbox rootdir and both gates are set exactly as the command sets them.
    """

    def __init__(self, sandbox: Sandbox, evidence_dir: Path) -> None:
        self.sandbox = sandbox
        self.evidence_file = evidence_dir / "evidence.txt"

    def module(
        self,
        body: str,
        *,
        extra_conftest: str = "",
        marked: bool = True,
        exports: Sequence[str] = ZERO_SKIP_EXPORT,
        filename: str = "test_surface.py",
        ini: str | None = SANDBOX_INI,
    ) -> None:
        source = body if marked else body.replace("pytestmark = pytest.mark.real_api", "")
        self.sandbox.write("reportlog.py", REPORT_LOG_PLUGIN)
        if self.sandbox.klass == "R":
            self.sandbox.conftest(extra_conftest)
            head = prelude(exports)
        else:
            self.sandbox.write("conftest.py", extra_conftest)
            head = "import pytest\n"
        if ini is not None:
            self.sandbox.pytester.makeini(ini)
        self.sandbox.write(filename, head + source)

    def command(
        self,
        node: str,
        *,
        source: str = lm.OFFICIAL_COMMAND,
        gate: bool = True,
        drop: Sequence[str] = (),
        replace: Mapping[str, str] | None = None,
        plugins: Sequence[str] = (),
    ) -> str:
        names = [
            "tripwires",
            *(["seams"] if self.sandbox.klass == "R" else []),
            "reportlog",
            *plugins,
        ]
        inserted = " ".join(f"-p {name}" for name in names)
        command = source.replace("-m pytest -m real_api", f"-m pytest {inserted} -m real_api")
        selector = node.split("::")[-1]
        pattern = re.escape(lm._TEST_MODULE) + r" \\\n  -k \w+"
        command, count = re.subn(pattern, f"{node} \\\\\n  -k {selector}", command)
        assert count == 1
        command = command.replace('"$PWD/src"', '"$SRC"')
        if not gate:
            command = command.replace(f"{lm.GATE_ENV}=1 ", "", 1)
        for flag in drop:  # a negative control declares each token it removes
            assert f" {flag}" in command
            command = command.replace(f" {flag}", "", 1)
        for old, new in (replace or {}).items():
            assert old in command
            command = command.replace(old, new, 1)
        return command

    def assert_declared_differences(
        self,
        command: str,
        node: str,
        *,
        source: str,
        drop: Sequence[str],
        replace: Mapping[str, str],
        plugins: Sequence[str],
        gate: bool,
    ) -> None:
        """S8: the argv differs from the constant by exactly the declared closed set."""
        selector = node.split("::")[-1]
        removed, added = token_delta(source, command)
        names = [
            "tripwires",
            *(["seams"] if self.sandbox.klass == "R" else []),
            "reportlog",
            *plugins,
        ]
        want_removed: Counter[str] = Counter(["PYTHONPATH=$PWD/src", lm._TEST_MODULE])
        want_removed[source.split("-k ")[1].split()[0]] += 1
        want_added: Counter[str] = Counter(["PYTHONPATH=$SRC", node, selector])
        for name in names:
            want_added["-p"] += 1
            want_added[name] += 1
        if not gate:
            want_removed[f"{lm.GATE_ENV}=1"] += 1
        for flag in drop:
            want_removed.update(shlex.split(flag))
        for old, new in replace.items():
            gone, came = token_delta(old, new)
            want_removed.update(gone)
            want_added.update(came)
        assert removed == want_removed, (removed - want_removed, want_removed - removed)
        assert added == want_added, (added - want_added, want_added - added)
        tokens = shlex.split(command.replace("\\\n", " "))
        first = tokens.index("pytest") + 1
        assert tokens[first : first + 2] == ["-p", "tripwires"]  # the tripwire is the first -p

    @staticmethod
    def vacuous(
        saved: str, status: int, *, pipefail: bool, allow_empty: bool, allow_warnings: bool
    ) -> list[str]:
        """A scenario that was deselected (exit 5) or warned about an unregistered marker fails."""
        problems = []
        if pipefail and status == 5 and not allow_empty:
            problems.append("no tests collected (exit 5): a vacuous scenario")
        if not allow_warnings and re.search(r"(?:^|, )[0-9]+ warnings?(?:,| in )", saved, re.M):
            problems.append("a warning count: an unregistered marker or an unexpected warning")
        return problems

    def run(
        self,
        node: str,
        *,
        pipefail: bool = True,
        gate: bool = True,
        drop: Sequence[str] = (),
        replace: Mapping[str, str] | None = None,
        source: str = lm.OFFICIAL_COMMAND,
        env: Mapping[str, str] | None = None,
        plugins: Sequence[str] = (),
        pythonpath_extra: Sequence[Path] = (),
        expect_hits: bool = False,
        allow_empty: bool = False,
        allow_warnings: bool = False,
        positive_control: bool = False,
    ) -> Ran:
        assert BASH is not None
        replace = dict(replace or {})
        command = self.command(
            node, source=source, gate=gate, drop=drop, replace=replace, plugins=plugins
        )
        self.assert_declared_differences(
            command,
            node,
            source=source,
            drop=drop,
            replace=replace,
            plugins=plugins,
            gate=gate,
        )
        selector = node.split("::")[-1]
        if self.sandbox.klass == "S":  # S3: the token cannot name or match any real live test
            assert "official_live_evidence" not in selector
            assert "readiness_probe_only" not in selector
            for path in self.sandbox.pytester.path.rglob("*.py"):
                if path.name not in ("tripwires.py", "seams.py"):
                    text = path.read_text()
                    assert "official_live_evidence" not in text
                    assert "readiness_probe_only" not in text
        else:  # R4: one real test, selected by a ``-k`` that cannot match the other one
            other = (
                "test_readiness_probe_only"
                if "official" in selector
                else "test_official_live_evidence"
            )
            assert (
                selector in (OFFICIAL_NODE.split("::")[-1], READINESS_NODE.split("::")[-1])
                or other not in selector
            )
            assert selector not in other
        script = (lm.PIPEFAIL_LINE + "\n" if pipefail else "") + command
        scratch_src = self.sandbox.pytester.path
        child = self.sandbox.child_environment(env)
        src = str(REPO_ROOT / "src") if self.sandbox.klass == "R" else str(scratch_src)
        src = os.pathsep.join([src, *(str(x) for x in pythonpath_extra)])
        child.update(PY=sys.executable, SRC=src, EVIDENCE_FILE=str(self.evidence_file))
        self.evidence_file.unlink(missing_ok=True)
        (self.sandbox.pytester.path / "report_log.jsonl").unlink(missing_ok=True)
        done = subprocess.run(
            [BASH, "-c", script],
            cwd=self.sandbox.pytester.path,
            env=child,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        self.sandbox.assert_clean_run(expect_hits=expect_hits)
        log = self.sandbox.pytester.path / "report_log.jsonl"
        reports = tuple(json.loads(x) for x in log.read_text().splitlines()) if log.exists() else ()
        saved = self.evidence_file.read_text()
        if not positive_control:
            problems = self.vacuous(
                saved,
                done.returncode,
                pipefail=pipefail,
                allow_empty=allow_empty,
                allow_warnings=allow_warnings or node.endswith("test_warning"),
            )
            assert problems == [], problems
        else:
            self.evidence_file.unlink()  # a positive control's capture is never evidence
            saved = ""
        return Ran(
            done.returncode, saved, done.stdout, done.stderr, reports, (), control=positive_control
        )


@pytest.fixture
def exact(sandbox: Sandbox, tmp_path_factory: pytest.TempPathFactory) -> Exact:
    return Exact(sandbox, tmp_path_factory.mktemp("evidence"))


@pytest.fixture
def exact_scratch(scratch: Sandbox, tmp_path_factory: pytest.TempPathFactory) -> Exact:
    return Exact(scratch, tmp_path_factory.mktemp("evidence"))


def evidence_records(text: str) -> list[dict[str, Any]]:
    return [
        json.loads(line[len("EVIDENCE ") :])
        for line in text.splitlines()
        if line.startswith("EVIDENCE ")
    ]


class TestOutputSurface:
    """H21: private logs and the flags of the authorized commands."""

    AUTHORIZED_FLAGS = tuple(authorized_flags(lm.OFFICIAL_COMMAND))

    def test_the_sandbox_runs_the_flags_the_module_authorizes(self) -> None:
        assert self.AUTHORIZED_FLAGS == (
            "-m",
            "real_api",
            "-q",
            "--color=no",
            "--show-capture=no",
            "--disable-warnings",
            "--tb=no",
            "-rN",
            "-p",
            "no:cacheprovider",
        )
        assert authorized_flags(lm.READINESS_ONLY_COMMAND) == list(self.AUTHORIZED_FLAGS)

    def test_the_detector_sees_the_secret_on_the_old_surface(self, sandbox: Sandbox) -> None:
        """Positive control: with ``caplog.at_level(DEBUG)`` and ``-rA`` the record is printed."""
        sandbox.conftest()
        sandbox.write("test_control.py", prelude(()) + CONTROL_BODY)
        result = sandbox.run("test_control.py", "-m", "real_api", "-rA", "-q")
        out = result.stdout.str()
        assert SECRET in out and "Captured log" in out
        # ... and the authorized flags hide even that record.
        result = sandbox.run("test_control.py", "-m", "real_api", "-q", "--show-capture=no")
        assert SECRET not in result.stdout.str()

    def test_the_output_grammar_rejects_unvetted_lines(self) -> None:
        assert output_problems("") == []
        assert output_problems("EVIDENCE " + json.dumps({"outcome": "ok"})) == []
        assert output_problems("EVIDENCE " + json.dumps({"stdout": "x"}))  # not allowlisted
        assert output_problems("EVIDENCE not-json")
        assert output_problems(f"DEBUG {SECRET}")
        assert output_problems("----- Captured log call -----x")
        assert output_problems("Skipping non-JSON line from CLI stdout: x")

    @pytest.mark.parametrize(
        "line",
        [
            "E   RuntimeError: boom",  # a traceback line
            ">   assert x == 1",  # a source line
            "    some_source_line()",
            "tmp_path = PosixPath('/tmp/x')",  # a fixture argument
            "tmp_path = 1",
            "test_surface.py:12: RuntimeError",  # a location line
            "/Users/x/.claude/x.py:1: KeyboardInterrupt",
            "asyncio.exceptions.CancelledError",
            "FAILED test_surface.py::test_x - CancelledError: message",
            "ERROR test_surface.py - boom",
            "unexpected exception: bad name!",
            "interrupted: details withheld plus more",
            "warnings summary",
            "=== FAILURES ===",
            "rootdir: /x",
            "plugins: anyio-4",
        ],
    )
    def test_the_output_grammar_has_no_traceback_or_location_allowance(self, line: str) -> None:
        assert output_problems(line), line

    @pytest.mark.parametrize(
        "line",
        [
            "unexpected exception: CancelledError",
            "unexpected exception",
            "harness failure",
            "case_failed:HarnessFailure",
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! KeyboardInterrupt !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
            "interrupted: details withheld",
            "(to show a full traceback on KeyboardInterrupt use --full-trace)",
            "evidence_fallback_failed: L1",
        ],
    )
    def test_the_output_grammar_accepts_the_fixed_forms(self, line: str) -> None:
        assert output_problems(line) == [], line

    def test_the_classifier_takes_the_output_and_the_status_only(self) -> None:
        """No per-test or per-exception-type carve-out can be passed in."""
        assert list(inspect.signature(output_problems).parameters) == ["text"]
        assert list(inspect.signature(lm.classify_capture).parameters) == [
            "text",
            "pipeline_status",
        ]

    def test_the_local_path_detector_finds_paths(self) -> None:
        assert local_path_problems("x /Users/someone/y")
        assert local_path_problems("pytest-of-someone")
        assert local_path_problems("clean text") == []


def scenario_status(name: str) -> int:
    return SCENARIOS[name][0]


@needs_bash
class TestOutputMatrix:
    """H31: the exact command under ``bash`` with ``pipefail`` and ``tee``, one run per scenario.

    Class R (the real gate fixture, evidence plugin and sanitizer are the code under test) with the
    exact command including the ``env -u`` prefix, ``--tb=no -rN`` and ``--color=no``.
    """

    @pytest.mark.parametrize("name", list(SCENARIOS))
    def test_saved_output_is_only_fixed_text_and_validated_evidence(
        self, exact: Exact, name: str
    ) -> None:
        ret, rendered = SCENARIOS[name]
        exact.module(SURFACE_BODY)
        ran = exact.run(f"test_surface.py::{name}")
        out = ran.saved
        assert ran.returncode == ret, out  # ``pipefail`` preserves pytest's status through tee
        assert ran.shown == out and ran.stderr == ""  # tee saved exactly what was piped
        for part in PARTS:
            assert plant(name.removeprefix("test_"), part) not in out
        assert SECRET not in out  # not the DEBUG record, nor fd 1 / fd 2 / print output
        assert "LEAKY-FIXTURE" not in out and "CHAINED" not in out
        assert "Captured" not in out and "Skipping non-JSON" not in out
        assert "warnings summary" not in out.lower()
        assert output_problems(out) == [], out  # every line is a form of the closed grammar
        assert local_path_problems(out, exact.sandbox.pytester.path) == [], out
        for marker in ("Traceback", "site-packages", "tmp_path =", "asyncio.", "raise ", "assert "):
            assert marker not in out, marker
        for banned in ("FAILURES", "ERRORS", "short test summary", "FAILED ", "ERROR ", "rootdir"):
            assert banned not in out, banned  # ``--tb=no -rN -q``: none of these is printed
        records = evidence_records(out)
        assert [r.get("case", "run") for r in records] == ["L0", "run"], out
        assert records[0]["canary_scan"] == list(lm.EMPTY_SCAN)
        assert "claude subscription live evidence" in out  # emitted without ``-s``
        # pytest's own rendering of the failure is read through the report log: fixed text only
        if rendered is not None:
            node = f"test_surface.py::{name}"
            when = "setup" if name == "test_setup_error" else "call"
            when = "teardown" if name == "test_teardown_error" else when
            assert ran.rendered(node, when) == rendered
        # the closed-grammar classifier accepts the capture as a structurally valid record
        verdict = "readiness_only" if ret == 0 else "failure_record"
        assert ran.verdict == (verdict, "ok"), (ran.verdict, out)
        if ret == 2:
            lines = out.splitlines()
            assert sum(bool(re.fullmatch(r"!+ KeyboardInterrupt !+", ln)) for ln in lines) == 1
            assert lines.count("interrupted: details withheld") == 1
            assert (
                lines.count("(to show a full traceback on KeyboardInterrupt use --full-trace)") == 1
            )

    def test_a_passing_control_returns_zero_and_a_failure_does_not(self, exact: Exact) -> None:
        exact.module(SURFACE_BODY)
        assert exact.run("test_surface.py::test_pass").returncode == 0
        assert exact.run("test_surface.py::test_unexpected_exception").returncode == 1

    @pytest.mark.parametrize(
        ("name", "status"),
        [("test_unexpected_exception", 1), ("test_keyboard_interrupt", 2)],
    )
    def test_without_pipefail_the_failure_status_is_masked(
        self, exact: Exact, name: str, status: int
    ) -> None:
        """Positive control: ``tee`` succeeds, so only ``pipefail`` preserves the failure."""
        exact.module(SURFACE_BODY)
        masked = exact.run(f"test_surface.py::{name}", pipefail=False)
        assert masked.returncode == 0
        assert "1 failed" in masked.saved or "KeyboardInterrupt" in masked.saved
        assert exact.run(f"test_surface.py::{name}").returncode == status

    def test_the_command_is_the_modules_constant_with_only_the_declared_differences(
        self, exact: Exact
    ) -> None:
        command = exact.command("test_surface.py::test_pass")
        for flag in TestOutputSurface.AUTHORIZED_FLAGS:
            assert flag in command
        assert command.rstrip().endswith('2>&1 | tee "$EVIDENCE_FILE"')
        for banned in (" -rA", " -s ", "--capture=no", "PYTEST_DISABLE_PLUGIN_AUTOLOAD"):
            assert banned not in command
        assert exact.evidence_file.parent != exact.sandbox.pytester.path
        assert not exact.evidence_file.is_relative_to(exact.sandbox.pytester.path)
        removed, added = token_delta(lm.OFFICIAL_COMMAND, command)
        assert removed == Counter(
            ["PYTHONPATH=$PWD/src", lm._TEST_MODULE, "official_live_evidence"]
        )
        assert added == Counter(
            [
                "PYTHONPATH=$SRC",
                "-p",
                "-p",
                "-p",
                "tripwires",
                "seams",
                "reportlog",
                "test_surface.py::test_pass",
                "test_pass",
            ]
        )


# ---------------------------------------------------------------------------
# H27: the report sanitizer on ordinary failures
# ---------------------------------------------------------------------------

# Records what pytest does with the exception and the report *after* the sanitizer ran, in the
# sandbox's conftest (a plain hook, not the sanitizer under test).
SPY_CONFTEST = """
import json

import pytest

STATE = {}


def pytest_runtest_setup(item):
    STATE["module"] = item.module


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    if call.excinfo is not None and call.when == "call":
        STATE["exc"] = call.excinfo.value
    return report


def pytest_runtest_logreport(report):
    if report.when == "call":
        STATE["outcome"] = report.outcome
        rep = report.longrepr
        STATE["longrepr"] = rep if isinstance(rep, str) else "<" + type(rep).__name__ + ">"
        STATE["sections"] = len(report.sections)


def pytest_keyboard_interrupt(excinfo):
    STATE["exc"] = excinfo.value


def pytest_sessionfinish(session, exitstatus):
    module, exc = STATE.get("module"), STATE.get("exc")
    same = None if exc is None else {
        "original": exc is module.ORIGINAL,
        "context": exc.__context__ is module.CTX,
        "cause": exc.__cause__ is module.CAUSE,
        "traceback": exc.__traceback__ is not None,
        "args": exc.args == module.ARGS,
        "type": type(exc) is type(module.ORIGINAL),
    }
    with open("spy.json", "w") as handle:
        json.dump(
            {
                "same": same,
                "outcome": STATE.get("outcome"),
                "longrepr": STATE.get("longrepr"),
                "sections": STATE.get("sections"),
            },
            handle,
        )
"""

IDENTITY_BODY = """

pytestmark = pytest.mark.real_api
CTX = RuntimeError("PLANTED-identity-ctx-4417")
CAUSE = ValueError("PLANTED-identity-cause-4417")
ORIGINAL = OSError("PLANTED-identity-msg-4417")
ORIGINAL.__context__ = CTX
ORIGINAL.__cause__ = CAUSE
ARGS = ORIGINAL.args


def test_identity(pytestconfig):
    print("captured stdout PLANTED-identity-stdout-4417")
    raise ORIGINAL
"""

INTERRUPT_IDENTITY_BODY = """

import asyncio

pytestmark = pytest.mark.real_api
CTX = RuntimeError("PLANTED-identity-ctx-4417")
CAUSE = ValueError("PLANTED-identity-cause-4417")
ORIGINAL = KeyboardInterrupt("PLANTED-identity-msg-4417")
ORIGINAL.__context__ = CTX
ORIGINAL.__cause__ = CAUSE
ARGS = ORIGINAL.args


def test_identity(pytestconfig):
    async def runner(case):
        raise ORIGINAL

    async def go():
        await lm.run_ordered_cases(
            {lm.Case.L1: runner},
            quota=lm.QuotaCounter(),
            emit=lambda record: None,
            cases=(lm.Case.L1,),
        )

    asyncio.run(go())  # the harness re-raises the very same object
"""

PREREQUISITE_BODY = """

pytestmark = pytest.mark.real_api
_real = lm.register_report_sanitizer


def _then_boom(config):
    _real(config)  # the sanitizer is registered now ...
    raise OSError("PLANTED-prerequisite-msg-4417")  # ... and the next prerequisite fails


lm.register_report_sanitizer = _then_boom


def test_anything():
    raise AssertionError("the test body never runs")
"""

UNGATED_BODY = """

CTX = RuntimeError("PLANTED-ungated-ctx-4417")


def test_unexpected():
    raise OSError("PLANTED-ungated-msg-4417")


def test_interrupt():
    raise KeyboardInterrupt("PLANTED-ungated-interrupt-4417")
"""

DROP_MEMO_CONFTEST = """
import pytest

_KEPT = {}


def pytest_sessionstart(session):
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    _KEPT["value"] = reporter._keyboardinterrupt_memo
    del reporter._keyboardinterrupt_memo


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    reporter._keyboardinterrupt_memo = _KEPT["value"]  # so pytest itself can unconfigure
"""


def spy_of(sandbox: Sandbox) -> dict[str, Any]:
    return json.loads((sandbox.pytester.path / "spy.json").read_text())


@needs_bash
class TestReportSanitizer:
    """H27: every failed report, in every phase, is rendered from fixed text only."""

    def test_an_ordinary_failure_renders_only_the_class(self, exact: Exact) -> None:
        exact.module(SURFACE_BODY)
        ran = exact.run("test_surface.py::test_exception_message")
        assert ran.returncode == 1
        assert "provider said" not in ran.saved
        assert ran.rendered("test_surface.py::test_exception_message") == (
            f"{UNEXPECTED}: RuntimeError"
        )

    @pytest.mark.parametrize(
        ("name", "rendered"),
        [
            ("test_harness_failure", "case_failed:HarnessFailure"),
            ("test_timeout", "inconclusive:HarnessFailure"),
            ("test_aggregate_failure", SCENARIOS["test_aggregate_failure"][1]),
        ],
    )
    def test_an_expected_harness_failure_renders_its_fixed_enum_text(
        self, exact: Exact, name: str, rendered: str
    ) -> None:
        exact.module(SURFACE_BODY)
        ran = exact.run(f"test_surface.py::{name}")
        assert ran.returncode == 1
        assert ran.rendered(f"test_surface.py::{name}") == rendered

    def test_arbitrary_failure_text_is_never_rendered(self, exact: Exact) -> None:
        body = SURFACE_BODY + (
            "\n\ndef test_free_text(pytestconfig):\n"
            "    _emit(pytestconfig, lm.Outcome.CASE_FAILED)\n"
            "    pytest.fail('FREE-TEXT-FAILURE-4417 /Users/planted', pytrace=False)\n"
        )
        exact.module(body)
        ran = exact.run("test_surface.py::test_free_text")
        assert ran.returncode == 1
        assert "FREE-TEXT-FAILURE-4417" not in ran.saved and "/Users/" not in ran.saved
        assert ran.rendered("test_surface.py::test_free_text") == "harness failure"
        assert output_problems(ran.saved) == []

    def test_setup_and_teardown_failures_are_sanitized_too(self, exact: Exact) -> None:
        exact.module(SURFACE_BODY)
        for name in ("test_setup_error", "test_teardown_error"):
            ran = exact.run(f"test_surface.py::{name}")
            assert ran.returncode == 1
            assert plant(name.removeprefix("test_"), "msg") not in ran.saved
            when = name.split("_")[1]
            rendered = ran.rendered(f"test_surface.py::{name}", when)
            assert rendered == f"{UNEXPECTED}: RuntimeError"

    def test_the_sanitizer_is_registered_only_under_both_gates(self, sandbox: Sandbox) -> None:
        """One gate is not enough: the default rendering (and the secret) is unchanged."""
        sandbox.conftest()
        sandbox.pytester.makeini(SANDBOX_INI)
        sandbox.write("test_ungated.py", prelude(ZERO_SKIP_EXPORT) + UNGATED_BODY)
        plant_text = "PLANTED-ungated-msg-4417"
        env_only = sandbox.run("test_ungated.py::test_unexpected", "-q")  # no ``-m``
        assert plant_text in env_only.stdout.str() and env_only.ret == 1
        marker_only = sandbox.run(
            "test_ungated.py::test_unexpected", "-q", *ALL_MARKERS, gate=False
        )
        assert plant_text in marker_only.stdout.str() and marker_only.ret == 1
        neither = sandbox.run("test_ungated.py::test_unexpected", "-q", gate=False)
        assert plant_text in neither.stdout.str() and neither.ret == 1
        # both gates: the same test module, sanitized
        both = sandbox.run("test_ungated.py::test_unexpected", "-q", *ALL_MARKERS)
        assert plant_text not in both.stdout.str() and both.ret == 1
        assert f"{UNEXPECTED}: OSError" in both.stdout.str()
        assert sandbox.hits() == []

    def test_the_sanitizer_is_registered_before_the_first_prerequisite(self, exact: Exact) -> None:
        """A prerequisite that raises an unexpected exception is already rendered sanitized."""
        exact.module(PREREQUISITE_BODY)
        ran = exact.run("test_surface.py::test_anything")
        assert ran.returncode == 1
        assert "PLANTED-prerequisite-msg-4417" not in ran.saved
        assert "the test body never runs" not in ran.saved
        assert ran.rendered("test_surface.py::test_anything", "setup") == f"{UNEXPECTED}: OSError"
        assert output_problems(ran.saved) == []

    def test_a_missing_terminal_reporter_is_still_reported_as_fixed_text(
        self, sandbox: Sandbox
    ) -> None:
        sandbox.conftest()
        sandbox.pytester.makeini(SANDBOX_INI)
        sandbox.write("test_surface.py", prelude(ZERO_SKIP_EXPORT) + SURFACE_BODY)
        result = sandbox.run(
            "test_surface.py::test_pass", "-m", "real_api", "-p", "no:terminal", "--junitxml=o.xml"
        )
        assert result.ret != 0
        text = (sandbox.pytester.path / "o.xml").read_text()
        assert "prereq_terminalreporter_missing:HarnessFailure" in text
        assert sandbox.hits() == []

    def test_the_original_exception_and_the_outcome_are_untouched(
        self, sandbox: Sandbox, exact: Exact
    ) -> None:
        """Identity, context, cause, traceback, outcome and status: the same with and without."""
        exact.module(IDENTITY_BODY, extra_conftest=SPY_CONFTEST)
        sanitized = exact.run("test_surface.py::test_identity")
        gated = spy_of(sandbox)
        unmarked = IDENTITY_BODY.replace("pytestmark = pytest.mark.real_api", "")
        sandbox.write("test_plain.py", unmarked)
        plain = sandbox.run("test_plain.py::test_identity", "-q", gate=False)
        ungated = spy_of(sandbox)
        untouched = dict.fromkeys(
            ("original", "context", "cause", "traceback", "args", "type"), True
        )
        assert gated["same"] == ungated["same"] == untouched
        assert gated["outcome"] == ungated["outcome"] == "failed"
        assert sanitized.returncode == plain.ret == 1
        # only the rendering differs: sanitized text and no captured sections ...
        assert gated["longrepr"] == f"{UNEXPECTED}: OSError" and gated["sections"] == 0
        # ... against pytest's own exception report and a capture section without the sanitizer
        assert ungated["longrepr"].startswith("<") and ungated["sections"] >= 1
        for part in ("msg", "ctx", "cause", "stdout"):
            assert f"PLANTED-identity-{part}-4417" not in sanitized.saved

    def test_an_exception_inside_the_sanitizer_does_not_change_the_outcome(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It never raises into pytest; a report it cannot render is still sanitized and failed."""

        class Report:
            failed = True
            sections: list[tuple[str, str]] = [("Captured stdout call", "PLANTED-x")]
            longrepr: object = "PLANTED-unsanitized"

        def run(report: object) -> object:
            wrapper = lm.ReportSanitizer().pytest_runtest_makereport(
                object(), SimpleNamespace(excinfo=None)
            )
            next(wrapper)
            try:
                wrapper.send(report)
            except StopIteration as stop:
                return stop.value
            raise AssertionError("the wrapper did not finish")

        def explode(excinfo: object) -> str:
            raise RuntimeError("PLANTED-render")

        monkeypatch.setattr(lm, "render_failure", explode)
        report = Report()
        assert run(report) is report
        assert report.failed and report.sections == []
        assert report.longrepr == UNEXPECTED  # fixed text, never the original

        class Stubborn:
            failed = True

            @property
            def sections(self) -> list[object]:
                return []

            @sections.setter
            def sections(self, value: object) -> None:
                raise RuntimeError("cannot assign")

            @property
            def longrepr(self) -> str:
                return "kept"

            @longrepr.setter
            def longrepr(self, value: object) -> None:
                raise RuntimeError("cannot assign")

        stubborn = Stubborn()
        assert run(stubborn) is stubborn  # an assignment failure never reaches pytest

        passing = SimpleNamespace(failed=False, sections=[("x", "y")], longrepr=None)
        assert run(passing) is passing and passing.sections == [("x", "y")]

    def test_the_real_render_is_total(self) -> None:
        for weird in (None, object(), SimpleNamespace(value=BaseException()), SimpleNamespace()):
            assert lm.render_failure(weird).startswith((UNEXPECTED, "harness failure"))

    def test_no_exemption_exists_anywhere(self) -> None:
        """No per-test or per-exception-type carve-out in the module, these tests or the checker."""
        banned = ("allow_" + "traceback", "TRACEBACK" + "_LINE")
        for path in (LIVE_MODULE, Path(__file__)):
            tree = ast.parse(path.read_text())
            names: set[str] = set()
            for node in ast.walk(tree):
                for attr in ("id", "arg", "name", "attr"):
                    value = getattr(node, attr, None)
                    if isinstance(value, str):
                        names.add(value)
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    names.add(node.value)
            assert not names & set(banned), path.name
        assert "allow" not in " ".join(inspect.signature(output_problems).parameters)


# ---------------------------------------------------------------------------
# H28: the KeyboardInterrupt sanitizer
# ---------------------------------------------------------------------------


@needs_bash
class TestInterruptSanitizer:
    @pytest.mark.parametrize("name", ["test_keyboard_interrupt", "test_keyboard_interrupt_chained"])
    def test_the_interrupt_output_is_the_fixed_banner_only(self, exact: Exact, name: str) -> None:
        exact.module(SURFACE_BODY)
        ran = exact.run(f"test_surface.py::{name}")
        assert ran.returncode == 2
        lines = [ln for ln in ran.saved.splitlines() if not ln.startswith("EVIDENCE ")]
        banner = [i for i, ln in enumerate(lines) if re.fullmatch(r"!+ KeyboardInterrupt !+", ln)]
        assert len(banner) == 1
        rest = lines[banner[0] + 1 :]
        assert rest[0] == "interrupted: details withheld"
        # pytest's own fixed hint line is the only other text after the banner
        assert rest[1] == "(to show a full traceback on KeyboardInterrupt use --full-trace)"
        # after pytest's own fixed hint there is only its closing summary line
        assert len(rest) == 3 and re.fullmatch(
            r"(?:no tests ran|\d+ \w+(?:, \d+ \w+)*) in [\d.]+s", rest[2]
        )
        key = name.removeprefix("test_")
        for part in ("msg", "ctx", "cause"):
            assert plant(key, part) not in ran.saved
        assert "LEAKY-FIXTURE" not in ran.saved
        assert local_path_problems(ran.saved, exact.sandbox.pytester.path) == []
        assert re.search(r"\.py:\d+", ran.saved) is None  # no location line
        assert "KeyboardInterrupt:" not in ran.saved  # no ``KeyboardInterrupt: <message>``
        assert output_problems(ran.saved) == []

    def test_the_interrupt_is_the_original_object_through_the_harness(
        self, sandbox: Sandbox, exact: Exact
    ) -> None:
        exact.module(INTERRUPT_IDENTITY_BODY, extra_conftest=SPY_CONFTEST)
        ran = exact.run("test_surface.py::test_identity")
        assert ran.returncode == 2
        spy = spy_of(sandbox)
        assert spy["same"] == dict.fromkeys(
            ("original", "context", "cause", "traceback", "args", "type"), True
        )
        assert "HarnessFailure" not in ran.saved and "harness failure" not in ran.saved
        assert "PLANTED-identity" not in ran.saved

    def test_with_the_gates_inactive_the_default_rendering_is_unchanged(
        self, sandbox: Sandbox
    ) -> None:
        sandbox.conftest()
        sandbox.pytester.makeini(SANDBOX_INI)
        sandbox.write("test_ungated.py", prelude(ZERO_SKIP_EXPORT) + UNGATED_BODY)
        result = sandbox.run("test_ungated.py::test_interrupt", "-q", gate=False)
        out = result.stdout.str()
        assert result.ret == 2
        assert "PLANTED-ungated-interrupt-4417" in out  # the message
        assert re.search(r"\.py:\d+", out)  # pytest's location line
        assert "interrupted: details withheld" not in out

    def test_a_missing_private_reporter_attribute_fails_closed_before_any_tripwire(
        self, exact: Exact
    ) -> None:
        exact.module(SURFACE_BODY, extra_conftest=DROP_MEMO_CONFTEST)
        ran = exact.run("test_surface.py::test_pass")
        assert ran.returncode == 1
        assert f"{lm.Outcome.PREREQ_REPORT_SANITIZER_UNAVAILABLE.value}:HarnessFailure" in ran.saved
        # the test body never ran, but the evidence plugin was registered before the sanitizer, so
        # the failure is recorded: exactly one run-level record, Path B, for every selected case
        (record,) = evidence_records(ran.saved)
        assert (
            record["primary_failure"]
            == "session:prereq_report_sanitizer_unavailable:HarnessFailure"
        )
        assert record["not_executed"] == ",".join(
            f"{c}:not_executed_after_safety_failure" for c in lm.CASE_NAMES
        )
        assert output_problems(ran.saved) == []
        assert ran.verdict == ("failure_record", "ok")

    def test_the_replacement_record_is_never_none_and_carries_no_path(self) -> None:
        record = lm.FixedInterruptRecord()
        assert record.reprcrash is not None and record.reprcrash.message == "KeyboardInterrupt"
        out = io.StringIO()
        writer = SimpleNamespace(line=lambda text, **kw: out.write(text + "\n"))
        record.toterminal(writer)
        record.reprcrash.toterminal(writer)
        assert out.getvalue() == "interrupted: details withheld\n" * 2
        assert local_path_problems(out.getvalue()) == []


# ---------------------------------------------------------------------------
# H29: class rendering of unexpected exceptions and cancellations
# ---------------------------------------------------------------------------


def excinfo_of(exc: BaseException) -> pytest.ExceptionInfo[BaseException]:
    try:
        raise exc
    except BaseException:
        return pytest.ExceptionInfo.from_current()


def named(name: str, base: type[BaseException] = Exception) -> BaseException:
    return type(name, (base,), {})(f"message {name!r} PLANTED-class-4417")


class TestExceptionRendering:
    @pytest.mark.parametrize(
        ("exc", "expected"),
        [
            (OSError("PLANTED-class-4417"), f"{UNEXPECTED}: OSError"),
            (lm.EvidenceError("PLANTED-class-4417"), f"{UNEXPECTED}: EvidenceError"),
            (asyncio.CancelledError(), f"{UNEXPECTED}: CancelledError"),
            (asyncio.CancelledError("PLANTED-class-4417"), f"{UNEXPECTED}: CancelledError"),
            (KeyError("PLANTED-class-4417"), f"{UNEXPECTED}: KeyError"),
            (named("Ok_Name_1"), f"{UNEXPECTED}: Ok_Name_1"),
            (named("_"), f"{UNEXPECTED}: _"),
            (named("A" * 64), f"{UNEXPECTED}: {'A' * 64}"),
        ],
    )
    def test_the_class_name_is_rendered_and_nothing_else(
        self, exc: BaseException, expected: str
    ) -> None:
        text = lm.render_failure(excinfo_of(exc))
        assert text == expected
        assert "PLANTED" not in text

    @pytest.mark.parametrize(
        "name",
        [
            "Errør",  # non-ASCII letters (``str.isidentifier`` accepts these)
            "Ж",
            "Bad\x01Name",  # control characters
            "Bad\nName",
            "A" * 65,  # over-length
            "not-an-identifier",
            "1Leading",
            "with space",
            "",
            "‮evil",
            "Nameé",
        ],
    )
    def test_an_unsafe_class_name_renders_the_bare_form(self, name: str) -> None:
        assert lm.render_failure(excinfo_of(named(name))) == UNEXPECTED
        assert lm.exception_class_of(named(name)) == lm.UNKNOWN_EXCEPTION
        assert lm.exception_class_of(named(name, BaseException)) == lm.UNKNOWN_EXCEPTION

    def test_str_isidentifier_would_have_accepted_a_non_ascii_name(self) -> None:
        """Why the pattern is ASCII: the naive check accepts what the design forbids."""
        assert "Errør".isidentifier()
        assert lm.exception_class_of(named("Errør")) == lm.UNKNOWN_EXCEPTION

    def test_a_failed_exception_renders_only_a_fixed_form(self) -> None:
        for text in ("case_failed:HarnessFailure", "prereq_cli_missing:HarnessFailure"):
            try:
                pytest.fail(text, pytrace=False)
            except pytest.fail.Exception:
                info = pytest.ExceptionInfo.from_current()
            assert lm.render_failure(info) == text
        for text in ("free text /Users/x", "", "case_failed:Badé", "made_up:HarnessFailure\n"):
            try:
                pytest.fail(text, pytrace=False)
            except pytest.fail.Exception:
                info = pytest.ExceptionInfo.from_current()
            assert lm.render_failure(info) == "harness failure"

    @pytest.mark.parametrize(
        "text",
        [
            "case_failed:HarnessFailure",
            "live_opt_in_error:LiveOptInError",
            "cases: L0:ok; first_failure: none:incomplete:none",
            "cases: L0:ok,L1:case_failed; first_failure: L1:case_failed:HarnessFailure; "
            "also: L1:descendant_leak,L1:canary_leak",
            "cases: L0:not_executed_after_safety_failure; first_failure: "
            "session:prereq_cli_missing:HarnessFailure",
        ],
    )
    def test_the_fixed_grammar_accepts_the_harness_forms(self, text: str) -> None:
        assert lm.is_fixed_failure_text(text)

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "free text",
            "made_up:HarnessFailure",
            "case_failed:Badé",
            "case_failed:HarnessFailure ",
            "case_failed:HarnessFailure\n",
            "case_failed:HarnessFailure\nmore",
            "cases: L9:ok; first_failure: none:incomplete:none",
            "cases: L0:ok; first_failure: L1:case_failed:HarnessFailure; also: secret",
            "cases: L0:ok; first_failure: L1:case_failed:/Users/x",
            "cases: L0:ok",
            None,
            b"case_failed:HarnessFailure",
            42,
        ],
    )
    def test_the_fixed_grammar_rejects_everything_else(self, text: object) -> None:
        assert not lm.is_fixed_failure_text(text)

    def test_a_str_subclass_is_never_rendered(self) -> None:
        class Sneaky(str):
            def __str__(self) -> str:
                return "/Users/leak"

        assert not lm.is_fixed_failure_text(Sneaky("case_failed:HarnessFailure"))

    @needs_bash
    @pytest.mark.parametrize("name", ["Errør", "Bad-Name", "C" * 70])
    def test_an_unsafe_class_in_a_real_run_renders_the_bare_form(
        self, exact: Exact, name: str
    ) -> None:
        body = SURFACE_BODY + (
            "\n\ndef test_weird_class(pytestconfig):\n"
            "    _emit(pytestconfig, lm.Outcome.CASE_FAILED)\n"
            f"    raise type({ascii(name)}, (Exception,), {{}})('PLANTED-weird-msg-4417')\n"
        )
        exact.module(body)
        ran = exact.run("test_surface.py::test_weird_class")
        assert ran.returncode == 1
        assert "PLANTED-weird-msg-4417" not in ran.saved and name not in ran.saved
        assert ran.rendered("test_surface.py::test_weird_class") == UNEXPECTED
        assert output_problems(ran.saved) == []

    @needs_bash
    def test_cancelled_error_is_not_exempted(self, exact: Exact) -> None:
        exact.module(SURFACE_BODY)
        for name in ("test_cancelled_error", "test_cancelled_error_chained"):
            ran = exact.run(f"test_surface.py::{name}")
            assert ran.returncode == 1
            rendered = ran.rendered(f"test_surface.py::{name}")
            assert rendered == f"{UNEXPECTED}: CancelledError"
            assert output_problems(ran.saved) == []  # no traceback, no allowance


# ---------------------------------------------------------------------------
# H30: warnings
# ---------------------------------------------------------------------------


@needs_bash
class TestWarnings:
    PLANTS = (
        plant("warning", "msg"),
        plant("warning", "cause"),
        plant("warning", "ctx"),
        "/Users/planted/.claude/x.py",
    )

    def test_a_planted_warning_does_not_reach_the_saved_output(self, exact: Exact) -> None:
        exact.module(SURFACE_BODY)
        ran = exact.run("test_surface.py::test_warning")
        assert ran.returncode == 0
        for planted in self.PLANTS:
            assert planted not in ran.saved
        assert "warnings summary" not in ran.saved.lower()
        assert "DeprecationWarning" not in ran.saved and "ResourceWarning" not in ran.saved
        assert local_path_problems(ran.saved, exact.sandbox.pytester.path) == []
        assert output_problems(ran.saved) == []
        assert [r.get("case") for r in evidence_records(ran.saved)] == ["L0", None]

    def test_without_the_flag_the_same_run_prints_them(self, exact: Exact) -> None:
        """Positive control: the test can see the warning text when the flag is absent."""
        exact.module(SURFACE_BODY)
        ran = exact.run("test_surface.py::test_warning", drop=["--disable-warnings"])
        assert plant("warning", "msg") in ran.saved
        assert "/Users/planted/.claude/x.py" in ran.saved
        assert "warnings summary" in ran.saved.lower()

    @pytest.mark.parametrize("command", [lm.READINESS_ONLY_COMMAND, lm.OFFICIAL_COMMAND])
    def test_both_command_constants_carry_the_flag(self, command: str) -> None:
        tokens = shlex.split(command.replace("\\\n", " "))
        assert tokens.count("--disable-warnings") == 1
        assert "-W" not in tokens and "-p" in tokens

    def test_the_sanitizer_never_touches_warning_counters(self, exact: Exact) -> None:
        """The count line still says how many warnings there were: nothing is reset or hidden."""
        exact.module(SURFACE_BODY)
        ran = exact.run("test_surface.py::test_warning")
        assert re.search(r"1 passed, 3 warnings in [\d.]+s", ran.saved), ran.saved
        source = inspect.getsource(lm.ReportSanitizer) + inspect.getsource(
            lm.register_report_sanitizer
        )
        for private in ("stats", "_numcollected", "warning", "_warn", "hasopt", "reportchars"):
            assert private not in source, private


# ---------------------------------------------------------------------------
# H12: the private pytest state the sanitizer relies on
# ---------------------------------------------------------------------------


class TestReporterPins:
    """H12: a pytest change that breaks the sanitizer fails offline, not during a live run."""

    def test_the_terminal_reporter_keeps_its_interrupt_record(
        self, pytester: pytest.Pytester
    ) -> None:
        from _pytest.terminal import TerminalReporter

        config = pytester.parseconfig()
        reporter = TerminalReporter(config)
        assert hasattr(reporter, "_keyboardinterrupt_memo")
        assert reporter._keyboardinterrupt_memo is None
        assert callable(reporter._report_keyboardinterrupt)
        assert callable(reporter.pytest_keyboard_interrupt)

    def test_pytest_renders_the_fixed_record_as_the_banner_and_the_fixed_line(
        self, pytester: pytest.Pytester
    ) -> None:
        from _pytest._io import TerminalWriter
        from _pytest.terminal import TerminalReporter

        config = pytester.parseconfig()
        reporter = TerminalReporter(config)
        sink = io.StringIO()
        reporter._tw = TerminalWriter(sink)
        reporter._keyboardinterrupt_memo = cast("Any", lm.FixedInterruptRecord())
        reporter._report_keyboardinterrupt()
        lines = sink.getvalue().splitlines()
        assert re.fullmatch(r"!+ KeyboardInterrupt !+", lines[0])
        assert lines[1:] == [
            "interrupted: details withheld",
            "(to show a full traceback on KeyboardInterrupt use --full-trace)",
        ]

    def test_a_string_longrepr_is_what_pytest_prints_and_summarizes(self) -> None:
        from _pytest._io import TerminalWriter
        from _pytest.reports import TestReport
        from _pytest.terminal import _get_line_with_reprcrash_message

        report = TestReport(
            nodeid="t.py::test_x",
            location=("t.py", 1, "test_x"),
            keywords={},
            outcome="failed",
            longrepr=f"{UNEXPECTED}: OSError",
            when="call",
        )
        sink = io.StringIO()
        report.toterminal(TerminalWriter(sink))
        assert sink.getvalue().splitlines()[-1] == f"{UNEXPECTED}: OSError"
        config = SimpleNamespace(
            option=SimpleNamespace(verbose=0, force_short_summary=False),
            get_verbosity=lambda *a: 0,
            cwd_relative_nodeid=lambda nodeid: nodeid,
            hook=SimpleNamespace(pytest_report_teststatus=lambda **kw: ("failed", "F", "FAILED")),
        )
        line = _get_line_with_reprcrash_message(config, report, TerminalWriter(io.StringIO()), {})  # type: ignore[arg-type]
        assert line.endswith(f"- {UNEXPECTED}: OSError")

    def test_the_hook_specifications_the_sanitizer_implements_exist(self) -> None:
        from _pytest import hookspec

        makereport = inspect.signature(hookspec.pytest_runtest_makereport)
        assert list(makereport.parameters) == ["item", "call"]
        interrupt = inspect.signature(hookspec.pytest_keyboard_interrupt)
        assert list(interrupt.parameters) == ["excinfo"]
        for name in ("pytest_runtest_makereport", "pytest_keyboard_interrupt"):
            impl = getattr(lm.ReportSanitizer, name)
            assert inspect.isgeneratorfunction(impl)  # a ``wrapper=True`` hook
            assert getattr(impl, "pytest_impl", None) is not None

    def test_a_failed_report_can_be_rewritten_the_way_the_sanitizer_does(self) -> None:
        from _pytest.reports import TestReport

        report = TestReport(
            nodeid="t.py::test_x",
            location=("t.py", 1, "test_x"),
            keywords={},
            outcome="failed",
            longrepr="original",
            when="call",
            sections=[("Captured stdout call", "x")],
        )
        assert report.failed and report.sections == [("Captured stdout call", "x")]
        report.sections = []
        report.longrepr = "replaced"
        assert report.failed and report.sections == [] and report.longrepr == "replaced"

    def test_a_missing_reporter_record_is_unavailable(self) -> None:
        config = make_config(reporter=SimpleNamespace(stats={}))  # no ``_keyboardinterrupt_memo``
        with raises_outcome(lm.Outcome.PREREQ_REPORT_SANITIZER_UNAVAILABLE) as info:
            lm.register_report_sanitizer(config)
        assert info.value.__cause__ is None and info.value.__suppress_context__  # never printed

    def test_a_missing_interrupt_hook_is_unavailable(self) -> None:
        config = make_config()
        config.hook = SimpleNamespace()  # no ``pytest_keyboard_interrupt``
        with raises_outcome(lm.Outcome.PREREQ_REPORT_SANITIZER_UNAVAILABLE):
            lm.register_report_sanitizer(config)
        assert config.pluginmanager.get_plugin(lm.REPORT_SANITIZER_NAME) is None

    def test_a_failed_registration_is_unavailable(self) -> None:
        config = make_config()

        def refuse(plugin: object, name: str) -> None:
            raise RuntimeError("PLANTED-registration-4417")

        config.pluginmanager.register = refuse
        with raises_outcome(lm.Outcome.PREREQ_REPORT_SANITIZER_UNAVAILABLE) as info:
            lm.register_report_sanitizer(config)
        assert "PLANTED" not in str(info.value)

    def test_registration_is_once_per_config_and_a_missing_reporter_is_left_to_the_next_check(
        self,
    ) -> None:
        config = make_config(reporter=None)
        first = lm.register_report_sanitizer(config)
        assert lm.register_report_sanitizer(config) is first
        assert config.pluginmanager.get_plugin(lm.REPORT_SANITIZER_NAME) is first
        with raises_outcome(lm.Outcome.PREREQ_TERMINALREPORTER_MISSING):
            lm.register_zero_skip_plugin(config)

    def test_the_fixture_registers_the_evidence_plugin_then_the_sanitizer(self) -> None:
        """AST: in the gate fixture the sanitizer registration precedes every other call."""
        tree = ast.parse(LIVE_MODULE.read_text())
        fixture = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "_register_zero_skip_reporter"
        )
        calls = [
            n.func.id
            for n in ast.walk(fixture)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        # both gates, then the evidence plugin (which holds the inert reporter lookup), then the
        # sanitizer as the very next call, and only then the failure path
        assert calls.index("gates_active") < calls.index("register_zero_skip_plugin")
        assert calls.index("register_zero_skip_plugin") + 1 == calls.index(
            "register_report_sanitizer"
        )  # adjacent: no call between the two registrations
        assert calls.index("register_report_sanitizer") < calls.index("fail_closed")


# ============================================================================
# H10 (unit): seeding and accounting
# ============================================================================


class Report:
    def __init__(self, outcome: str, *, wasxfail: str | None = None) -> None:
        self.outcome = outcome
        if wasxfail is not None:
            self.wasxfail = wasxfail


class TestZeroSkipUnit:
    def test_is_real_skip_excludes_expected_xfail(self) -> None:
        assert lm.is_real_skip(Report("skipped"))
        assert not lm.is_real_skip(Report("skipped", wasxfail="reason"))
        assert not lm.is_real_skip(Report("passed"))
        assert not lm.is_real_skip(Report("failed"))

    def test_seed_excludes_xfail_and_counts_prior_skips(self) -> None:
        reporter = FakeReporter(
            [Report("skipped"), Report("skipped", wasxfail="x"), Report("skipped")]
        )
        config = make_config(reporter=reporter)
        plugin = lm.register_zero_skip_plugin(config)
        assert plugin.skipped_reports == 2

    def test_increment_excludes_xfail_and_no_double_counting(self) -> None:
        config = make_config(reporter=FakeReporter([Report("skipped")]))
        plugin = lm.register_zero_skip_plugin(config)
        assert lm.register_zero_skip_plugin(config) is plugin  # once per config
        plugin.pytest_runtest_logreport(Report("skipped", wasxfail="x"))
        plugin.pytest_runtest_logreport(Report("passed"))
        assert plugin.skipped_reports == 1
        plugin.pytest_runtest_logreport(Report("skipped"))
        assert plugin.skipped_reports == 2

    def test_missing_terminal_reporter_fails_closed(self) -> None:
        with raises_outcome(lm.Outcome.PREREQ_TERMINALREPORTER_MISSING):
            lm.register_zero_skip_plugin(make_config(reporter=None))

    def test_sessionfinish_only_upgrades_a_passing_exit(self) -> None:
        plugin = lm.ZeroSkipPlugin(seed=1)
        session = SimpleNamespace(exitstatus=0)
        plugin.pytest_sessionfinish(session, 0)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
        failing = SimpleNamespace(exitstatus=pytest.ExitCode.TESTS_FAILED)
        plugin.pytest_sessionfinish(failing, pytest.ExitCode.TESTS_FAILED)
        assert failing.exitstatus == pytest.ExitCode.TESTS_FAILED
        clean = SimpleNamespace(exitstatus=0)
        lm.ZeroSkipPlugin(seed=0).pytest_sessionfinish(clean, 0)
        assert clean.exitstatus == 0

    def test_official_requires_pass_zero_skips_and_clean_tree(self) -> None:
        plugin = lm.ZeroSkipPlugin()
        assert not plugin.official
        plugin.ordered_test_passed, plugin.git_dirty = True, False
        plugin.canary_scans_complete = True
        assert plugin.official
        plugin.skipped_reports = 1
        assert not plugin.official
        plugin.skipped_reports, plugin.git_dirty = 0, True
        assert not plugin.official
        plugin.git_dirty, plugin.canary_scans_complete = False, False
        assert not plugin.official  # an incomplete or leaking canary scan is never official


# ============================================================================
# H8 (in-process): direct helper reuse
# ============================================================================


class Entered:
    """A fake external entry point; any call is recorded."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, *args: object, **kwargs: object) -> Any:
        self.calls.append("called")
        return ("", "")


def helper_invocations(entered: Entered, tmp_path: Path) -> list[tuple[str, Callable[[Any], Any]]]:
    def run_sync(coro_fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
        return lambda config: asyncio.run(coro_fn(config))

    class FakeAdapters:
        def __getattr__(self, name: str) -> Any:
            entered.calls.append(name)
            raise AssertionError("adapter entered")

    return [
        ("read_git_state", lambda c: lm.read_git_state(c, tmp_path, run=lambda argv: entered())),
        (
            "descendant_snapshot",
            lambda c: lm.descendant_snapshot(c, tmp_path, popen=entered),
        ),
        (
            "read_cli_version",
            lambda c: lm.read_cli_version(
                c, tmp_path, Path("/x/claude"), run=lambda argv: entered()
            ),
        ),
        (
            "resolve_cli_evidence",
            lambda c: lm.resolve_cli_evidence(c, tmp_path, run=lambda a: entered()),
        ),
        (
            "run_case",
            run_sync(lambda c: lm.run_case(c, tmp_path, lm.Case.L0, lambda case: entered())),
        ),
        (
            "probe_readiness",
            run_sync(lambda c: lm.probe_readiness(c, tmp_path, FakeAdapters())),  # ty: ignore[invalid-argument-type]
        ),
        (
            "run_official_session",
            run_sync(lambda c: lm.run_official_session(c, tmp_path, FakeAdapters())),  # ty: ignore[invalid-argument-type]
        ),
        ("common_preflight", lambda c: lm.common_preflight(c, tmp_path)),
    ]


class TestHelperReuse:
    @pytest.mark.parametrize(
        ("env_on", "config"),
        [
            (True, make_config(markexpr=None)),
            (True, make_config(markexpr="")),
            (False, make_config(markexpr="real_api")),
            (False, make_config(markexpr=None)),
            (True, make_config(markexpr="real_api", numprocesses=2)),
            (True, make_config(markexpr="not real_api")),
            (True, make_config(markexpr="real_api and (")),  # unparsable: fails closed
        ],
        ids=[
            "env-only-none",
            "env-only-empty",
            "markexpr-only",
            "neither",
            "xdist-numprocesses",
            "not-real_api",
            "invalid-expression",
        ],
    )
    def test_h8_every_helper_rejects_before_any_entry(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        env_on: bool,
        config: Any,
    ) -> None:
        monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
        if env_on:
            monkeypatch.setenv(lm.GATE_ENV, "1")
        else:
            monkeypatch.delenv(lm.GATE_ENV, raising=False)
        entered = Entered()
        for name, invoke in helper_invocations(entered, tmp_path):
            with pytest.raises(lm.LiveOptInError):
                invoke(config)
            assert entered.calls == [], name

    def test_h8_env_value_must_be_exactly_one(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        entered = Entered()
        for value in ("0", "true", "yes", "1 ", "", "01"):
            monkeypatch.setenv(lm.GATE_ENV, value)
            for name, invoke in helper_invocations(entered, tmp_path):
                with pytest.raises(lm.LiveOptInError):
                    invoke(make_config())
                assert entered.calls == [], (value, name)

    def test_h8_xdist_worker_environment(
        self, monkeypatch: pytest.MonkeyPatch, gates_on: None
    ) -> None:
        monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
        with pytest.raises(lm.LiveOptInError):
            lm.require_live_optin(make_config())

    def test_h8_real_api_or_not_real_api_is_accepted_and_not_real_api_rejected(
        self, gates_on: None
    ) -> None:
        lm.require_live_optin(make_config("real_api or not real_api"))
        lm.require_live_optin(make_config("real_api"))
        lm.require_live_optin(make_config("real_api and not performance"))
        with pytest.raises(lm.LiveOptInError):
            lm.require_live_optin(make_config("not real_api"))
        assert lm.gates_active(make_config("real_api")) is True
        assert lm.gates_active(make_config("not real_api")) is False

    def test_h8_isolation_failure_precedes_every_entry_point(
        self, gates_on: None, tmp_path: Path
    ) -> None:
        """Both gates active, but ``tmp_path`` is not the fixture-redirected directory."""
        entered = Entered()
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        for name, invoke in helper_invocations(entered, foreign):
            with raises_outcome(lm.Outcome.ISOLATION_FIXTURES_MISSING):
                invoke(make_config())
            assert entered.calls == [], name

    def test_h8_file_console_failure_precedes_adapters(
        self, gates_on: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("conductor.cli.run._file_console", object())
        adapters = FakeAdapterSet()
        result = asyncio.run(
            lm.run_official_session(
                make_config(),
                tmp_path,
                adapters.as_set(),
                readiness_check=lambda: None,
                prereq_check=lambda: "bundled",
            )
        )
        assert result.session_failure == (lm.Outcome.PREREQ_FILE_CONSOLE_ACTIVE, "HarnessFailure")
        assert adapters.calls == []
        assert result.evidence == []
        assert {r.outcome for r in result.results} == {lm.Outcome.NOT_EXECUTED_AFTER_SAFETY_FAILURE}


# ============================================================================
# H11: isolation statics
# ============================================================================


class TestIsolationStatic:
    def test_real_fixtures_satisfy_the_prerequisite(self, tmp_path: Path) -> None:
        lm.assert_live_isolation(tmp_path)  # this file runs under the root conftest fixtures

    def _kwargs(self, tmp_path: Path) -> dict[str, Any]:
        home = tmp_path / "conductor-home"
        return {
            "runs_dir_fn": as_conftest_fn(lambda: tmp_path / "runs"),
            "pid_dir_fn": as_conftest_fn(lambda: tmp_path / "pids"),
            "gettempdir_fn": as_conftest_fn(lambda: str(tmp_path)),
            "environ": {
                "TMPDIR": str(tmp_path),
                "TEMP": str(tmp_path),
                "TMP": str(tmp_path),
                "CONDUCTOR_HOME": str(home),
            },
            "records_dir_fn": lambda: home / "runs",
            "event_root_fn": lambda: tmp_path / "conductor",
        }

    def test_fabricated_good_objects_pass(self, tmp_path: Path) -> None:
        lm.assert_live_isolation(tmp_path, **self._kwargs(tmp_path))

    def test_production_functions_are_not_called_when_a_static_check_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []

        def tripwire(name: str) -> Callable[[], Path]:
            def _fn() -> Path:
                calls.append(name)
                raise RuntimeError(name)

            return _fn

        monkeypatch.setattr("conductor.fleet.records.run_records_dir", tripwire("records"))
        monkeypatch.setattr("conductor.fleet.retention.event_log_root", tripwire("events"))
        kwargs = self._kwargs(tmp_path)
        kwargs.pop("records_dir_fn")
        kwargs.pop("event_root_fn")
        kwargs["environ"] = {**kwargs["environ"], "CONDUCTOR_HOME": "/somewhere/else"}
        with raises_outcome(lm.Outcome.ISOLATION_FIXTURES_MISSING):
            lm.assert_live_isolation(tmp_path, **kwargs)
        assert calls == []

    @pytest.mark.parametrize(
        "mutation",
        [
            "original_runs_dir",
            "wrong_file_runs_dir",
            "wrong_file_pid_dir",
            "gettempdir_not_redirected",
            "gettempdir_wrong_file",
            "tmpdir_wrong",
            "temp_unset",
            "conductor_home_outside",
            "conductor_home_unset",
            "runs_dir_behavior_outside",
            "pid_dir_behavior_outside",
            "records_dir_outside",
            "event_root_wrong",
            "behavior_raises",
        ],
    )
    def test_each_unsafe_condition_is_rejected(self, tmp_path: Path, mutation: str) -> None:
        kwargs = self._kwargs(tmp_path)
        env = dict(kwargs["environ"])
        production = REPO_ROOT / "src" / "conductor" / "rundir.py"
        outside = Path(tempfile.gettempdir()).parent / "elsewhere"

        from_file = relabel

        if mutation == "original_runs_dir":
            kwargs["runs_dir_fn"] = from_file(lambda: tmp_path / "runs", production)
        elif mutation == "wrong_file_runs_dir":
            kwargs["runs_dir_fn"] = lambda: tmp_path / "runs"  # defined in this test file
        elif mutation == "wrong_file_pid_dir":
            kwargs["pid_dir_fn"] = lambda: tmp_path / "pids"
        elif mutation == "gettempdir_not_redirected":
            kwargs["gettempdir_fn"] = as_conftest_fn(lambda: "/tmp")
        elif mutation == "gettempdir_wrong_file":
            kwargs["gettempdir_fn"] = lambda: str(tmp_path)
        elif mutation == "tmpdir_wrong":
            env["TMPDIR"] = "/tmp"
        elif mutation == "temp_unset":
            del env["TEMP"]
        elif mutation == "conductor_home_outside":
            env["CONDUCTOR_HOME"] = "/root/.conductor"
        elif mutation == "conductor_home_unset":
            del env["CONDUCTOR_HOME"]
        elif mutation == "runs_dir_behavior_outside":
            kwargs["runs_dir_fn"] = as_conftest_fn(lambda: Path("/root/.conductor/runs"))
        elif mutation == "pid_dir_behavior_outside":
            kwargs["pid_dir_fn"] = as_conftest_fn(lambda: outside)
        elif mutation == "records_dir_outside":
            kwargs["records_dir_fn"] = lambda: outside
        elif mutation == "event_root_wrong":
            kwargs["event_root_fn"] = lambda: tmp_path / "not-conductor"
        elif mutation == "behavior_raises":
            kwargs["records_dir_fn"] = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        kwargs["environ"] = env
        with raises_outcome(lm.Outcome.ISOLATION_FIXTURES_MISSING):
            lm.assert_live_isolation(tmp_path, **kwargs)

    def test_foreign_repo_conftest_is_rejected(self, tmp_path: Path) -> None:
        """A fixture whose code comes from *another* repository's conftest is not ours."""
        kwargs = self._kwargs(tmp_path)
        foreign = tmp_path / "other-repo" / "tests" / "conftest.py"
        kwargs["runs_dir_fn"] = relabel(kwargs["runs_dir_fn"], foreign)
        with raises_outcome(lm.Outcome.ISOLATION_FIXTURES_MISSING):
            lm.assert_live_isolation(tmp_path, **kwargs)

    def test_production_fixture_functions_are_rejected(self, tmp_path: Path) -> None:
        """Without the fixtures the *production* runs_dir/pid_dir are seen: unsafe."""
        import conductor.cli.pid
        import conductor.rundir

        original_runs = as_production(conductor.rundir.runs_dir)
        original_pid = as_production(conductor.cli.pid.pid_dir)
        kwargs = self._kwargs(tmp_path)
        kwargs["runs_dir_fn"] = original_runs
        kwargs["pid_dir_fn"] = original_pid
        with raises_outcome(lm.Outcome.ISOLATION_FIXTURES_MISSING):
            lm.assert_live_isolation(tmp_path, **kwargs)


def as_production(fn: Callable[..., Any]) -> Callable[..., Any]:
    return relabel(fn, REPO_ROOT / "src" / "conductor" / "rundir.py")


class TestSourceTree:
    def _layout(self, root: Path) -> tuple[Path, Path]:
        test_file = root / "tests" / "test_integration" / "test_x.py"
        src = root / "src" / "conductor"
        test_file.parent.mkdir(parents=True)
        src.mkdir(parents=True)
        test_file.write_text("")
        (src / "__init__.py").write_text("")
        return test_file, src / "__init__.py"

    def test_inside(self, tmp_path: Path) -> None:
        test_file, conductor_file = self._layout(tmp_path / "repo")
        lm.verify_source_tree(conductor_file, test_file)

    def test_sibling_checkout_rejected(self, tmp_path: Path) -> None:
        test_file, _ = self._layout(tmp_path / "worktree")
        _, other = self._layout(tmp_path / "main-checkout")
        with raises_outcome(lm.Outcome.SOURCE_TREE_MISMATCH):
            lm.verify_source_tree(other, test_file)

    def test_symlink_pointing_outside_rejected(self, tmp_path: Path) -> None:
        test_file, _ = self._layout(tmp_path / "worktree")
        _, other = self._layout(tmp_path / "main-checkout")
        link = tmp_path / "worktree" / "src" / "conductor" / "linked.py"
        link.symlink_to(other)
        with raises_outcome(lm.Outcome.SOURCE_TREE_MISMATCH):
            lm.verify_source_tree(link, test_file)

    def test_real_import_is_inside_this_repository(self) -> None:
        import conductor

        lm.verify_source_tree(conductor.__file__ or "", LIVE_MODULE)

    def test_git_state_parsing(self) -> None:
        sha = "a" * 40
        assert lm.parse_git_state(sha + "\n", "") == (sha, False)
        assert lm.parse_git_state(sha, " M file\n") == (sha, True)
        with pytest.raises(lm.HarnessFailure):
            lm.parse_git_state("not-a-sha", "")

    def test_git_state_reader_uses_injected_runner_after_gates(
        self, gates_on: None, tmp_path: Path
    ) -> None:
        answers = {"rev-parse": "b" * 40, "status": "?? x"}
        seen: list[str] = []

        def runner(argv: Sequence[str]) -> str:
            seen.append(argv[1])
            return answers[argv[1]]

        assert lm.read_git_state(make_config(), tmp_path, run=runner) == ("b" * 40, True)
        assert seen == ["rev-parse", "status"]


# ============================================================================
# H11: classifier
# ============================================================================


def obs(
    error: str | None = None, status: int | None = None, is_error: bool | None = None
) -> lm.Observation:
    return lm.Observation("ResultMessage", error, status, is_error)


class TestClassifier:
    non_retryable = ProviderError("x", is_retryable=False)

    def test_invalid_key_from_authentication_failed(self) -> None:
        got = lm.classify_l3([obs(error="authentication_failed")], [self.non_retryable], [])
        assert got is lm.Outcome.INVALID_KEY

    def test_invalid_key_from_401(self) -> None:
        assert lm.classify_l3([obs(status=401)], [self.non_retryable], []) is lm.Outcome.INVALID_KEY

    def test_fell_back_on_successful_agent_completed(self) -> None:
        assert (
            lm.classify_l3([], [], [{"type": "agent_completed"}]) is lm.Outcome.FELL_BACK_TO_LOGIN
        )
        event = SimpleNamespace(type="agent_completed")
        assert lm.classify_l3([], [], [event]) is lm.Outcome.FELL_BACK_TO_LOGIN

    def test_fell_back_beats_an_error_signal(self) -> None:
        got = lm.classify_l3([obs(status=401)], [self.non_retryable], [{"type": "agent_completed"}])
        assert got is lm.Outcome.FELL_BACK_TO_LOGIN

    def test_model_unavailable_on_404(self) -> None:
        got = lm.classify_l3([obs(status=404)], [self.non_retryable], [])
        assert got is lm.Outcome.MODEL_UNAVAILABLE

    def test_generic_non_retryable_is_inconclusive(self) -> None:
        assert lm.classify_l3([], [self.non_retryable], []) is lm.Outcome.INCONCLUSIVE
        assert lm.classify_l3([obs()], [self.non_retryable], []) is lm.Outcome.INCONCLUSIVE
        assert (
            lm.classify_l3([obs(error="server_error", status=500)], [self.non_retryable], [])
            is lm.Outcome.INCONCLUSIVE
        )

    def test_text_in_the_exception_never_counts(self) -> None:
        error = ProviderError("401 authentication_failed invalid api key", is_retryable=False)
        assert lm.classify_l3([], [error], []) is lm.Outcome.INCONCLUSIVE

    def test_signal_without_a_non_retryable_provider_error_is_inconclusive(self) -> None:
        signal = [obs(error="authentication_failed", status=401)]
        assert lm.classify_l3(signal, [], []) is lm.Outcome.INCONCLUSIVE
        assert lm.classify_l3(signal, [RuntimeError("x")], []) is lm.Outcome.INCONCLUSIVE
        retryable = ProviderError("x", is_retryable=True)
        assert lm.classify_l3(signal, [retryable], []) is lm.Outcome.INCONCLUSIVE

    def test_no_signals_at_all_is_inconclusive(self) -> None:
        assert lm.classify_l3([], [], []) is lm.Outcome.INCONCLUSIVE

    def test_exception_chain_is_walked(self) -> None:
        inner = ProviderError("x", is_retryable=False)
        outer = RuntimeError("wrapped")
        outer.__cause__ = inner
        chain = lm.exception_chain(outer)
        assert inner in chain
        got = lm.classify_l3([obs(status=401)], chain, [])
        assert got is lm.Outcome.INVALID_KEY


# ============================================================================
# H11: evidence
# ============================================================================


class TestEvidence:
    def test_accepts_every_allowed_shape(self) -> None:
        record = lm.evidence(
            case="L3",
            outcome=lm.Outcome.INVALID_KEY,
            git_sha="c" * 40,
            git_dirty=False,
            env_names_set=["ANTHROPIC_API_KEY"],
            env_names_removed=["ANTHROPIC_BASE_URL"],
            descendant_report=[{"pid": 12, "name": "node"}],
            elapsed_s=1.5,
            input_tokens=3,
            requested_model="claude-haiku-4-5",
            cli_version="2.1.150",
            adapter_outcome=lm.Outcome.INCONCLUSIVE,
            secondary_findings=["descendant_leak"],
            interrupted="none",
            canary_scan=list(lm.EMPTY_SCAN),
        )
        assert record["outcome"] == "invalid_key"
        assert record["canary_scan"] == list(lm.EMPTY_SCAN)
        assert lm.emit_evidence(record).startswith("EVIDENCE {")

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("unknown_key", 1),
            ("git_dirty", 1),  # int is not bool
            ("input_tokens", True),  # bool is not int
            ("elapsed_s", float("nan")),
            ("case", "L9"),
            ("outcome", "made_up"),
            ("env_names_set", {"ANTHROPIC_API_KEY": "sk-ant-api03-x"}),  # raw dict
            ("env_names_set", ["ANTHROPIC_API_KEY=sk-ant-api03-secret"]),  # a value, not a name
            ("env_names_set", ["lowercase"]),
            ("env_names_removed", "ANTHROPIC_API_KEY"),
            ("descendant_report", [{"pid": 1, "name": "x", "cmd": "secret"}]),
            ("descendant_report", [{"pid": "1", "name": "x"}]),
            ("billing_reason", "x" * 500),  # unbounded string
            ("billing_reason", "has spaces and $pecial"),
            ("billing_reason", "sk-ant-api03-leaked"),
            ("cli_version", "1.0; rm -rf /"),
            ("effective_model", ""),
            ("exception_class", "Not An Identifier"),
            ("ready", {"authMethod": "claude.ai", "email": "a@b.c"}),  # raw auth payload
        ],
    )
    def test_rejects(self, key: str, value: object) -> None:
        with pytest.raises(lm.EvidenceError) as info:
            lm.evidence(**{key: value})
        assert "sk-ant" not in str(info.value)
        assert "secret" not in str(info.value)

    def test_error_never_echoes_the_value_or_unknown_key(self) -> None:
        with pytest.raises(lm.EvidenceError) as info:
            lm.evidence(billing_reason="sk-ant-api03-LEAK-VALUE")
        assert "LEAK-VALUE" not in str(info.value)
        with pytest.raises(lm.EvidenceError) as info:
            lm.evidence(**{"sk-ant-api03-key-as-name": 1})
        assert "sk-ant" not in str(info.value)

    def test_emit_revalidates(self) -> None:
        with pytest.raises(lm.EvidenceError):
            lm.emit_evidence({"outcome": "ok", "surprise": 1})

    def test_key_allowlist_is_fixed(self) -> None:
        assert {"date_utc", "git_sha", "outcome", "pytest_version", "plugins"} <= lm.EVIDENCE_KEYS
        # one representation of ``official``: the G4 section line, never a record key
        assert not {"official", "skipped_reports", "zero_skip_verdict"} & lm.EVIDENCE_KEYS
        assert not any(k in lm.EVIDENCE_KEYS for k in ("env", "stdout", "stderr", "raw", "email"))
        assert {"adapter_outcome", "secondary_findings", "interrupted", "canary_scan"} <= (
            lm.EVIDENCE_KEYS
        )


class TestEvidenceContract:
    """The revision-4 fields: bounded fixed values, never free text, never a canary."""

    GOOD_SCAN = list(lm.EMPTY_SCAN)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("adapter_outcome", "made_up"),
            ("adapter_outcome", "RuntimeError: secret detail"),
            ("adapter_outcome", 7),
            ("secondary_findings", "canary_leak"),  # not a list
            ("secondary_findings", ["anything else"]),
            ("secondary_findings", ["canary_scan_incomplete"]),  # not a safety finding here
            ("secondary_findings", ["canary_leak", "canary_leak"]),  # duplicate
            ("secondary_findings", ["canary_leak", "descendant_leak", "canary_leak"]),
            ("interrupted", True),  # the old boolean shape
            ("interrupted", "KeyboardInterrupt: secret detail"),
            ("interrupted", "CancelledError"),
            ("cleanup_failed", ["secret detail"]),
            ("cleanup_failed", "scan"),
            ("cleanup_failed", ["scan"]),  # the removed step: no code path emits it
            ("cleanup_failed", ["evidence", "descendants"]),  # out of cleanup order
            ("cleanup_failed", ["descendants", "descendants"]),  # a duplicate
            ("cleanup_failed", []),
            ("canary_scan", "events=clean,console=clean"),  # the old free-text shape
            ("canary_scan", {"stdout_stderr": "clean"}),  # a mapping
            ("canary_scan", GOOD_SCAN[:-1]),  # missing an entry
            ("canary_scan", [*GOOD_SCAN, "tmp_files:clean"]),  # an extra entry
            ("canary_scan", [GOOD_SCAN[1], GOOD_SCAN[0], *GOOD_SCAN[2:]]),  # reordered
            ("canary_scan", ["stdout_stderr:leak: matched text", *GOOD_SCAN[1:]]),
            ("canary_scan", ["stdout_stderr:maybe", *GOOD_SCAN[1:]]),
            ("canary_scan", ["capfd:clean", *GOOD_SCAN[1:]]),  # a retired stream name
            ("canary_scan", [f"stdout_stderr:{CANARY}", *GOOD_SCAN[1:]]),
        ],
    )
    def test_rejects(self, key: str, value: object) -> None:
        with pytest.raises(lm.EvidenceError) as info:
            lm.evidence(**{key: value})
        assert "secret detail" not in str(info.value)
        assert CANARY not in str(info.value)

    def test_a_case_record_without_canary_scan_is_rejected(self) -> None:
        for case in ("L0", "L1", "L3", "L2"):
            with pytest.raises(lm.EvidenceError):
                lm.evidence(case=case, outcome=lm.Outcome.OK)
            assert lm.evidence(case=case, outcome=lm.Outcome.OK, canary_scan=self.GOOD_SCAN)
        # a session-level record describes no case scan
        assert lm.evidence(case="session", git_dirty=False)

    def test_accepts_every_fixed_value(self) -> None:
        for kind in lm.INTERRUPT_KINDS:
            assert lm.evidence(interrupted=kind)["interrupted"] == kind
        for finding in (
            [],
            ["canary_leak"],
            ["descendant_leak"],
            ["canary_leak", "descendant_leak"],
        ):
            assert lm.evidence(secondary_findings=finding)["secondary_findings"] == finding
        scan = [f"{name}:{state}" for name, state in zip(lm.REQUIRED_STREAMS, _STATES, strict=True)]
        assert lm.evidence(canary_scan=scan)["canary_scan"] == scan

    def test_arbitrary_text_cannot_enter_through_an_exception_or_a_log(self) -> None:
        """A unique exception message, log line, auth value and canary never reach a record."""
        unique = "UNIQUE-EXCEPTION-TEXT-7731"
        for value in (unique, f"{unique} {CANARY}", {"authMethod": unique}):
            for key in ("exception_class", "adapter_outcome", "interrupted", "secondary_findings"):
                with pytest.raises(lm.EvidenceError) as info:
                    lm.evidence(**{key: value})
                assert unique not in str(info.value) and CANARY not in str(info.value)


_STATES = ("clean", "leak", "not_available", "clean", "clean", "not_available", "clean", "leak")


# ============================================================================
# H11: canary
# ============================================================================


class TestCanary:
    def test_canary_shape_and_uniqueness(self) -> None:
        one, two = lm.make_canary(), lm.make_canary()
        assert one != two
        assert re.fullmatch(r"sk-ant-api03-CANARY-[0-9a-f]{32}-DO-NOT-USE", one)
        with pytest.raises(lm.HarnessFailure):
            lm.validate_canary("sk-ant-api03-real-looking-key")

    @pytest.mark.parametrize("stream", lm.REQUIRED_STREAMS)
    def test_positive_control_for_every_stream_category(self, stream: str) -> None:
        streams = clean_streams()
        streams[stream] = f"prefix {CANARY} suffix"
        with raises_outcome(lm.Outcome.CANARY_LEAK) as info:
            lm.assert_no_canary(CANARY, streams)
        assert stream in str(info.value)
        assert CANARY not in str(info.value)

    def test_clean_streams_pass(self) -> None:
        lm.assert_no_canary(CANARY, clean_streams())

    def test_fragment_of_twelve_characters_is_detected(self) -> None:
        streams = clean_streams()
        streams["console"] = "x " + CANARY[20:32] + " y"  # 12 characters of the random part
        with raises_outcome(lm.Outcome.CANARY_LEAK):
            lm.assert_no_canary(CANARY, streams)

    def test_short_fragment_is_not_a_leak(self) -> None:
        streams = clean_streams()
        streams["console"] = CANARY[20:31]  # 11 characters
        lm.assert_no_canary(CANARY, streams)

    def test_missing_stream_category_is_incomplete_not_a_pass(self) -> None:
        for missing in lm.REQUIRED_STREAMS:
            streams = clean_streams()
            del streams[missing]
            with raises_outcome(lm.Outcome.CANARY_SCAN_INCOMPLETE):
                lm.assert_no_canary(CANARY, streams)
        with raises_outcome(lm.Outcome.CANARY_SCAN_INCOMPLETE):
            lm.assert_no_canary(CANARY, {})  # the old "called with no streams" bug

    def test_exception_chain_scanning(self) -> None:
        cause = RuntimeError(f"key {CANARY}")
        top = ValueError("innocent")
        top.__cause__ = cause
        assert CANARY in lm.render_exception_chain(top)
        context_only = ValueError("innocent")
        context_only.__context__ = KeyError(CANARY)
        assert CANARY in lm.render_exception_chain(context_only)
        group = ExceptionGroup("g", [OSError(CANARY)])
        assert CANARY in lm.render_exception_chain(group)
        streams = clean_streams()
        streams["exceptions"] = top
        with raises_outcome(lm.Outcome.CANARY_LEAK):
            lm.assert_no_canary(CANARY, streams)

    def test_exception_chain_handles_cycles(self) -> None:
        a, b = RuntimeError("a"), RuntimeError("b")
        a.__cause__, b.__cause__ = b, a
        assert len(lm.exception_chain(a)) == 2

    def test_structured_and_bytes_streams(self) -> None:
        streams = clean_streams()
        streams["events"] = [{"type": "x", "data": {"k": CANARY}}]
        with raises_outcome(lm.Outcome.CANARY_LEAK):
            lm.assert_no_canary(CANARY, streams)
        streams = clean_streams()
        streams["stdout_stderr"] = CANARY.encode()
        with raises_outcome(lm.Outcome.CANARY_LEAK):
            lm.assert_no_canary(CANARY, streams)

    def test_tmp_files_stream_reads_files(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "log.txt").write_text(f"oops {CANARY}")
        streams = clean_streams()
        streams["tmp_files"] = lm.read_tmp_files(tmp_path)
        with raises_outcome(lm.Outcome.CANARY_LEAK):
            lm.assert_no_canary(CANARY, streams)

    def test_leak_message_is_fixed_text(self) -> None:
        streams = clean_streams()
        streams["evidence"] = CANARY
        with pytest.raises(lm.HarnessFailure) as info:
            lm.assert_no_canary(CANARY, streams)
        assert str(info.value) == "canary_leak: canary present in evidence"


# ============================================================================
# H11: model, quota, CLI class
# ============================================================================


class TestModel:
    def test_default_and_valid_overrides(self) -> None:
        assert lm.validate_model(None) == "claude-haiku-4-5"
        assert lm.validate_model("claude-haiku-4-5-20251001") == "claude-haiku-4-5-20251001"
        assert lm.validate_model("claude-sonnet-4@2025.01") == "claude-sonnet-4@2025.01"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "haiku",
            "Claude-haiku",
            "claude-haiku\n",  # ``$`` would accept a trailing newline
            "claude haiku",
            'claude-"haiku"',
            "claude-haiku;ls",
            "claude-$(id)",
            "claude-a/b",
            "claude-" + "a" * 62,
            "claude--x",
        ],
    )
    def test_strict_override_regex(self, bad: str) -> None:
        with raises_outcome(lm.Outcome.INVALID_MODEL_OVERRIDE):
            lm.validate_model(bad)

    def test_requested_and_effective_model_are_distinct(self) -> None:
        assert lm.check_effective_model("claude-haiku-4-5-20251001") == "claude-haiku-4-5-20251001"
        for empty in ("", "  ", None, 7):
            with raises_outcome(lm.Outcome.EFFECTIVE_MODEL_MISSING):
                lm.check_effective_model(empty)
        record = lm.evidence(
            requested_model="claude-haiku-4-5", effective_model="claude-haiku-4-5-20251001"
        )
        assert record["requested_model"] != record["effective_model"]

    def test_unpriced_models_fail(self) -> None:
        assert lm.check_priced(0.002) == 0.002
        for unpriced in (None, 0, 0.0, -1.0, True, float("nan"), "0.1"):
            with raises_outcome(lm.Outcome.UNPRICED_MODEL_LABEL_UNEXERCISED):
                lm.check_priced(unpriced)


class TestQuota:
    def test_fourth_attempt_is_refused(self) -> None:
        quota = lm.QuotaCounter()
        assert quota.ceiling == 3
        for expected in (1, 2, 3):
            quota.begin_attempt()
            assert quota.attempts == expected
        with raises_outcome(lm.Outcome.QUOTA_CEILING_EXCEEDED):
            quota.begin_attempt()
        assert quota.attempts == 3

    def test_custom_ceiling(self) -> None:
        quota = lm.QuotaCounter(1)
        quota.begin_attempt()
        with pytest.raises(lm.HarnessFailure):
            quota.begin_attempt()


class TestCliClass:
    bundled = Path("/venv/site-packages/claude_agent_sdk/_bundled/claude")

    def test_bundled(self) -> None:
        got = lm.classify_cli(self.bundled, bundled=self.bundled, bundled_exists=True, on_path=None)
        assert got == "bundled"

    def test_path_cli_rejected_when_bundled_exists(self) -> None:
        with raises_outcome(lm.Outcome.PREREQ_CLI_NOT_BUNDLED):
            lm.classify_cli(
                Path("/usr/local/bin/claude"),
                bundled=self.bundled,
                bundled_exists=True,
                on_path=Path("/usr/local/bin/claude"),
            )

    def test_path_and_fallback_when_no_bundled(self) -> None:
        on_path = Path("/usr/local/bin/claude")
        assert (
            lm.classify_cli(on_path, bundled=self.bundled, bundled_exists=False, on_path=on_path)
            == "path"
        )
        other = Path("/opt/claude")
        assert (
            lm.classify_cli(other, bundled=self.bundled, bundled_exists=False, on_path=on_path)
            == "fallback"
        )

    def test_missing(self) -> None:
        with raises_outcome(lm.Outcome.PREREQ_CLI_MISSING):
            lm.classify_cli(None, bundled=self.bundled, bundled_exists=True, on_path=None)

    def test_version_token(self) -> None:
        assert lm.parse_cli_version("2.1.150 (Claude Code)\n") == "2.1.150"
        for bad in ("", "  ", "2.1;rm", "x" * 41):
            with pytest.raises(lm.HarnessFailure):
                lm.parse_cli_version(bad)

    def test_check_prerequisites_order_and_fixed_enums(self, tmp_path: Path) -> None:
        sdk = tmp_path / "claude_agent_sdk"
        (sdk / "_bundled").mkdir(parents=True)
        (sdk / "_bundled" / "claude").write_text("")
        spec = SimpleNamespace(
            submodule_search_locations=[str(sdk)], origin=str(sdk / "__init__.py")
        )
        bundled = sdk / "_bundled" / "claude"

        def go(**overrides: Any) -> str:
            base: dict[str, Any] = {
                "find_spec": lambda name: spec,
                "find_cli": lambda: bundled,
                "which": lambda name: "/bin/x",
            }
            return lm.check_prerequisites(**{**base, **overrides})

        assert go() == "bundled"
        with raises_outcome(lm.Outcome.PREREQ_SDK_MISSING):
            go(find_spec=lambda name: None)
        with raises_outcome(lm.Outcome.PREREQ_CLI_MISSING):
            go(find_cli=lambda: None)
        with raises_outcome(lm.Outcome.PREREQ_PS_MISSING):
            go(which=lambda name: None if name == "ps" else "/bin/x")


# ============================================================================
# H11: state machine
# ============================================================================

O = lm.Outcome  # noqa: E741 - short alias keeps the transition table readable
S = lm.Case


class Scripted:
    """Injected async fake case runners; records order and quota state at entry."""

    def __init__(self, script: dict[lm.Case, object], quota: lm.QuotaCounter) -> None:
        self.script = script
        self.quota = quota
        self.called: list[lm.Case] = []
        self.attempts_at_entry: dict[lm.Case, int] = {}

    def runners(self) -> dict[lm.Case, Any]:
        def make(case: lm.Case) -> Callable[[lm.Case], Any]:
            async def run(_: lm.Case) -> Any:
                self.called.append(case)
                self.attempts_at_entry[case] = self.quota.attempts
                value = self.script.get(case, lm.EXPECTED_OUTCOME[case])
                if isinstance(value, BaseException):
                    raise value
                return value

            return run

        return {case: make(case) for case in lm.ORDER}


def run_machine(
    script: dict[lm.Case, object] | None = None,
    *,
    quota: lm.QuotaCounter | None = None,
    pre_hooks: dict[lm.Case, Callable[[], None]] | None = None,
) -> tuple[lm.SessionResult, Scripted, list[dict[str, object]]]:
    counter = quota or lm.QuotaCounter()
    scripted = Scripted(script or {}, counter)
    emitted: list[dict[str, object]] = []
    result = asyncio.run(
        lm.run_ordered_cases(
            scripted.runners(), quota=counter, emit=emitted.append, pre_hooks=pre_hooks
        )
    )
    return result, scripted, emitted


TABLE = [
    # (id, script, called, outcomes per case in order, succeeded)
    (
        "all-ok",
        {},
        [S.L0, S.L1, S.L3, S.L2],
        [O.OK, O.OK, O.INVALID_KEY, O.OK],
        True,
    ),
    (
        "l0-fails",
        {S.L0: O.NOT_LOGGED_IN},
        [S.L0],
        [O.NOT_LOGGED_IN] + [O.NOT_EXECUTED_AFTER_L0_FAILURE] * 3,
        False,
    ),
    (
        "l0-raises",
        {S.L0: RuntimeError("boom")},
        [S.L0],
        [O.CASE_FAILED] + [O.NOT_EXECUTED_AFTER_L0_FAILURE] * 3,
        False,
    ),
    (
        "l1-fails",
        {S.L1: O.INCONCLUSIVE},
        [S.L0, S.L1],
        [O.OK, O.INCONCLUSIVE, O.NOT_EXECUTED_AFTER_L1_FAILURE, O.NOT_EXECUTED_AFTER_L1_FAILURE],
        False,
    ),
    (
        "descendant-leak",
        {S.L1: lm.HarnessFailure(O.DESCENDANT_LEAK)},
        [S.L0, S.L1],
        [O.OK, O.DESCENDANT_LEAK] + [O.NOT_EXECUTED_AFTER_SAFETY_FAILURE] * 2,
        False,
    ),
    (
        "canary-leak-in-l3",
        {S.L3: lm.HarnessFailure(O.CANARY_LEAK)},
        [S.L0, S.L1, S.L3],
        [O.OK, O.OK, O.CANARY_LEAK, O.NOT_EXECUTED_AFTER_SAFETY_FAILURE],
        False,
    ),
    (
        "l3-fell-back",
        {S.L3: O.FELL_BACK_TO_LOGIN},
        [S.L0, S.L1, S.L3],
        [O.OK, O.OK, O.FELL_BACK_TO_LOGIN, O.NOT_EXECUTED_L3_FELL_BACK_TO_LOGIN],
        False,
    ),
    (
        "l3-inconclusive",
        {S.L3: O.INCONCLUSIVE},
        [S.L0, S.L1, S.L3],
        [O.OK, O.OK, O.INCONCLUSIVE, O.NOT_EXECUTED_L3_INCONCLUSIVE],
        False,
    ),
    (
        "l3-model-unavailable",
        {S.L3: O.MODEL_UNAVAILABLE},
        [S.L0, S.L1, S.L3],
        [O.OK, O.OK, O.MODEL_UNAVAILABLE, O.NOT_EXECUTED_L3_MODEL_UNAVAILABLE],
        False,
    ),
    (
        "l3-generic-exception-is-inconclusive",
        {S.L3: ProviderError("x", is_retryable=False)},
        [S.L0, S.L1, S.L3],
        [O.OK, O.OK, O.INCONCLUSIVE, O.NOT_EXECUTED_L3_INCONCLUSIVE],
        False,
    ),
    (
        "l3-ok-value-is-not-a-pass",
        {S.L3: O.OK},
        [S.L0, S.L1, S.L3],
        [O.OK, O.OK, O.OK, O.NOT_EXECUTED_L3_INCONCLUSIVE],
        False,
    ),
    (
        "l2-fails",
        {S.L2: O.INCONCLUSIVE},
        [S.L0, S.L1, S.L3, S.L2],
        [O.OK, O.OK, O.INVALID_KEY, O.INCONCLUSIVE],
        False,
    ),
]


class TestStateMachine:
    @pytest.mark.parametrize(
        ("script", "called", "outcomes", "succeeded"),
        [row[1:] for row in TABLE],
        ids=[row[0] for row in TABLE],
    )
    def test_transition_table(
        self,
        script: dict[lm.Case, object],
        called: list[lm.Case],
        outcomes: list[lm.Outcome],
        succeeded: bool,
    ) -> None:
        result, scripted, emitted = run_machine(script)
        assert scripted.called == called
        assert [r.outcome for r in result.results] == outcomes
        assert [r.case for r in result.results] == list(lm.ORDER)
        assert result.succeeded is succeeded
        assert len(emitted) == len(called)  # only executed cases emit evidence
        for record in emitted:
            lm.emit_evidence(record)  # every record passes the sanitizer

    def test_l3_invalid_key_alone_proceeds_to_l2(self) -> None:
        _, scripted, _ = run_machine({S.L3: O.INVALID_KEY})
        assert scripted.called[-1] is S.L2
        for other in (O.FELL_BACK_TO_LOGIN, O.INCONCLUSIVE, O.MODEL_UNAVAILABLE, O.OK):
            _, scripted, _ = run_machine({S.L3: other})
            assert S.L2 not in scripted.called, other

    def test_transition_function_is_pure_and_total(self) -> None:
        assert lm.not_executed_value(S.L0, O.OK) is None
        assert lm.not_executed_value(S.L1, O.OK) is None
        assert lm.not_executed_value(S.L3, O.INVALID_KEY) is None
        assert lm.not_executed_value(S.L2, O.INCONCLUSIVE) is None
        for safety in lm.SAFETY_OUTCOMES:
            for case in lm.ORDER:
                assert lm.not_executed_value(case, safety) is O.NOT_EXECUTED_AFTER_SAFETY_FAILURE

    def test_evidence_is_emitted_from_finally(self) -> None:
        result, _, emitted = run_machine({S.L1: RuntimeError("secret-detail")})
        record = emitted[-1]
        assert record["case"] == "L1"
        assert record["outcome"] == "case_failed"
        assert record["exception_class"] == "RuntimeError"
        assert "secret-detail" not in str(emitted)
        assert result.results[1].exc_class == "RuntimeError"

    def test_interruption_emits_evidence_then_reraises(self) -> None:
        counter = lm.QuotaCounter()
        scripted = Scripted({S.L1: asyncio.CancelledError()}, counter)
        emitted: list[dict[str, object]] = []

        async def go() -> None:
            await lm.run_ordered_cases(scripted.runners(), quota=counter, emit=emitted.append)

        with pytest.raises(asyncio.CancelledError):
            asyncio.run(go())
        case_records = [r for r in emitted if "case" in r]
        assert case_records[-1]["case"] == "L1"
        assert case_records[-1]["outcome"] == "interrupted"
        assert case_records[-1]["interrupted"] == "cancelled"

    @pytest.mark.parametrize("make", [KeyboardInterrupt, asyncio.CancelledError])
    def test_an_interrupt_after_completed_cases_keeps_them_and_is_the_primary_failure(
        self, make: Callable[[], BaseException]
    ) -> None:
        """L0 and L1 complete, L3 is interrupted: the earlier ``ok`` cases are never the failure."""

        def deterministic_clock() -> Callable[[], float]:
            ticks = iter(range(10_000))
            return lambda: float(next(ticks))

        async def go(
            script: dict[lm.Case, object],
            emitted: list[dict[str, object]],
            counter: lm.QuotaCounter,
        ) -> Scripted:
            scripted = Scripted(script, counter)
            await lm.run_ordered_cases(
                scripted.runners(), quota=counter, emit=emitted.append, clock=deterministic_clock()
            )
            return scripted

        baseline: list[dict[str, object]] = []
        asyncio.run(go({}, baseline, lm.QuotaCounter()))

        original = make()
        counter = lm.QuotaCounter()
        emitted: list[dict[str, object]] = []
        scripted = Scripted({S.L3: original}, counter)

        async def interrupted() -> None:
            await lm.run_ordered_cases(
                scripted.runners(),
                quota=counter,
                emit=emitted.append,
                clock=deterministic_clock(),
            )

        with pytest.raises(type(original)) as info:
            asyncio.run(interrupted())
        assert info.value is original  # the very same object, unchanged
        assert scripted.called == [S.L0, S.L1, S.L3]  # the later L2 never ran
        cases = [r for r in emitted if "case" in r]
        assert [r["case"] for r in cases] == ["L0", "L1", "L3"]
        assert cases[:2] == [r for r in baseline if r.get("case") in ("L0", "L1")]  # unchanged
        assert [r["outcome"] for r in cases[:2]] == ["ok", "ok"]
        assert cases[2]["outcome"] == "interrupted"
        assert cases[2]["interrupted"] in ("keyboard_interrupt", "cancelled")
        (run_level,) = [r for r in emitted if "case" not in r]
        assert emitted[-1] is run_level  # written last
        assert run_level["primary_failure"] == f"L3:interrupted:{type(original).__name__}"
        assert run_level["not_executed"] == "L2:not_executed_after_interrupt"
        assert run_level["quota_attempts_total"] == 2 and run_level["quota_ceiling"] == 3
        assert "ok" not in str(run_level["primary_failure"]).split(":")[1:2]
        for record in emitted:
            lm.emit_evidence(record)  # every record passes the sanitizer

    def test_quota_counter_increments_before_each_inference_runner(self) -> None:
        result, scripted, emitted = run_machine()
        assert scripted.attempts_at_entry == {S.L0: 0, S.L1: 1, S.L3: 2, S.L2: 3}
        assert result.quota_attempts == 3
        assert [r["attempted_quota_execution"] for r in emitted] == [False, True, True, True]

    def test_exhausted_quota_refuses_before_the_runner(self) -> None:
        quota = lm.QuotaCounter()
        quota.attempts = 3  # a fourth attempt
        result, scripted, _ = run_machine(quota=quota)
        assert scripted.called == [S.L0]
        assert result.results[1].outcome is O.QUOTA_CEILING_EXCEEDED
        assert result.results[2].outcome is O.NOT_EXECUTED_AFTER_SAFETY_FAILURE
        assert quota.attempts == 3

    def test_pairing_hooks_abort_before_the_case(self) -> None:
        def boom() -> None:
            raise lm.HarnessFailure(O.L2_L3_NOT_PAIRED)

        result, scripted, _ = run_machine(pre_hooks={S.L2: boom})
        assert S.L2 not in scripted.called
        assert result.results[-1].outcome is O.L2_L3_NOT_PAIRED
        assert result.succeeded is False
        # the ceiling was not consumed by the refused case
        assert result.quota_attempts == 2

    def test_preflight_failure_runs_nothing_and_records_no_case_evidence(self) -> None:
        counter = lm.QuotaCounter()
        scripted = Scripted({}, counter)
        emitted: list[dict[str, object]] = []

        def preflight() -> None:
            raise lm.HarnessFailure(O.ISOLATION_FIXTURES_MISSING)

        result = asyncio.run(
            lm.run_session(
                preflight=preflight, runners=scripted.runners(), quota=counter, emit=emitted.append
            )
        )
        assert scripted.called == [] and emitted == [] and result.evidence == []
        assert {r.outcome for r in result.results} == {O.NOT_EXECUTED_AFTER_SAFETY_FAILURE}
        assert result.primary_failure == "session:isolation_fixtures_missing:HarnessFailure"
        assert result.succeeded is False

    def test_live_opt_in_error_is_a_session_failure_not_a_skip(self) -> None:
        counter = lm.QuotaCounter()

        def preflight() -> None:
            raise lm.LiveOptInError

        result = asyncio.run(
            lm.run_session(
                preflight=preflight,
                runners=Scripted({}, counter).runners(),
                quota=counter,
                emit=lambda r: None,
            )
        )
        assert result.session_failure == (O.LIVE_OPT_IN_ERROR, "LiveOptInError")

    def test_l3_l2_workflows_differ_only_by_auth_mode_and_env_names_equal(self) -> None:
        variants = lm.build_variants(lm.EXAMPLE_PATH.read_text(), CANARY, os.environ)
        l3, l2 = variants[S.L3], variants[S.L2]
        assert lm.config_diff_paths(l3.config, l2.config) == ["workflow.runtime.provider.auth_mode"]
        assert (l3.auth_mode, l2.auth_mode) == ("auto", "subscription")
        assert set(l3.env.set_names) == set(l2.env.set_names) == {"ANTHROPIC_API_KEY"}
        assert set(l3.env.removed_names) == set(l2.env.removed_names)
        assert CANARY not in repr(l3) and CANARY not in repr(l3.env)
        lm.assert_config_paired(l3, l2)
        lm.assert_env_paired(l3, l2)

    def test_pairing_detects_config_and_env_drift(self) -> None:
        variants = lm.build_variants(lm.EXAMPLE_PATH.read_text(), CANARY, {})
        l3, l2 = variants[S.L3], variants[S.L2]
        drifted = {**l2.config, "agents": [{"name": "other"}]}
        with raises_outcome(O.L2_L3_NOT_PAIRED):
            lm.assert_config_paired(l3, lm.CaseVariant(S.L2, "subscription", drifted, l2.env))
        with raises_outcome(O.L2_L3_NOT_PAIRED):
            lm.assert_config_paired(l3, lm.CaseVariant(S.L2, "subscription", l3.config, l2.env))
        other_env = lm.EnvPlan(("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"), (), dict(l2.env.values))
        with raises_outcome(O.L2_L3_NOT_PAIRED):
            lm.assert_env_paired(l3, lm.CaseVariant(S.L2, "subscription", l2.config, other_env))
        removed_env = lm.EnvPlan(l2.env.set_names, ("ANTHROPIC_BASE_URL",), dict(l2.env.values))
        with raises_outcome(O.L2_L3_NOT_PAIRED):
            lm.assert_env_paired(l3, lm.CaseVariant(S.L2, "subscription", l2.config, removed_env))
        other_value = lm.EnvPlan(l2.env.set_names, l2.env.removed_names, {"ANTHROPIC_API_KEY": "x"})
        with raises_outcome(O.L2_L3_NOT_PAIRED):
            lm.assert_env_paired(l3, lm.CaseVariant(S.L2, "subscription", l2.config, other_value))

    def test_scrub_list_names_only_route_variables(self) -> None:
        env = {
            "ANTHROPIC_API_KEY": "x",
            "ANTHROPIC_BASE_URL": "y",
            "CLAUDE_CODE_OAUTH_TOKEN": "z",
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "HTTPS_PROXY": "p",
            "PATH": "/bin",
            "CLAUDE_CODE_ENTRYPOINT": "cli",
        }
        assert lm.scrub_route_names(env) == (
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_USE_BEDROCK",
        )


class TestAggregation:
    def test_success_requires_every_intended_outcome(self) -> None:
        result, _, _ = run_machine()
        assert result.succeeded
        lm.finalize(result)  # no failure

    def test_final_aggregate_fails_despite_nonempty_evidence(self) -> None:
        """Replacing the aggregate criteria by ``len(evidence) > 0`` must be caught."""
        result, _, emitted = run_machine({S.L0: O.NOT_LOGGED_IN})
        assert len(result.evidence) > 0 and len(emitted) > 0
        with pytest.raises(pytest.fail.Exception):
            lm.finalize(result)

    @pytest.mark.parametrize("row", [r for r in TABLE if not r[4]], ids=lambda r: r[0])
    def test_every_failing_row_fails_the_aggregate(self, row: tuple[Any, ...]) -> None:
        result, _, _ = run_machine(row[1])
        with pytest.raises(pytest.fail.Exception):
            lm.finalize(result)

    def test_primary_enum_and_exception_class_survive_later_failures(self) -> None:
        result, _, _ = run_machine(
            {S.L1: ProviderError("secret-message-xyz"), S.L2: O.INCONCLUSIVE}
        )
        text = lm.aggregate_text(result)
        assert "first_failure: L1:case_failed:ProviderError" in text
        assert text.startswith("cases: L0:ok,L1:case_failed,")
        assert "secret-message-xyz" not in text
        with pytest.raises(pytest.fail.Exception) as info:
            lm.finalize(result)
        assert "secret-message-xyz" not in str(info.value)

    def test_incomplete_results_are_not_success(self) -> None:
        result, _, _ = run_machine()
        result.results.pop()
        assert result.succeeded is False
        result2, _, _ = run_machine()
        result2.results.reverse()
        assert result2.succeeded is False

    def test_run_level_record_is_sanitized(self) -> None:
        result, _, _ = run_machine({S.L3: O.FELL_BACK_TO_LOGIN})
        record = lm.run_level_record(result)
        assert record["not_executed"] == "L2:not_executed_l3_fell_back_to_login"
        assert record["primary_failure"] == "L3:fell_back_to_login:none"
        assert record["quota_attempts_total"] == 2


# ============================================================================
# H12: private-API and structure pins
# ============================================================================


def module_ast() -> ast.Module:
    return ast.parse(LIVE_MODULE.read_text())


def module_level_functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Functions defined directly at module level (never nested or inside a class)."""
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def missing_module_level_fixtures(source: str, names: Sequence[str]) -> list[str]:
    """Names that are *not* a module-level ``@pytest.fixture`` function in ``source``.

    Only a top-level, fixture-decorated function satisfies the check: a nested function or a
    method with the expected name would not override a conftest fixture, and a plain function
    is not a fixture at all.
    """
    functions = module_level_functions(ast.parse(source))
    return [
        name
        for name in names
        if name not in functions
        or not any("fixture" in ast.unparse(d) for d in functions[name].decorator_list)
    ]


class TestPrivateApiPins:
    def test_provider_private_signatures(self) -> None:
        pytest.importorskip("claude_agent_sdk")
        from conductor.providers import claude_agent_sdk as provider

        # Read from source: the repository's autouse fixture replaces the live attribute.
        tree = ast.parse((REPO_ROOT / "src/conductor/providers/claude_agent_sdk.py").read_text())
        methods = {
            n.name: n
            for c in tree.body
            if isinstance(c, ast.ClassDef) and c.name == "ClaudeAgentSdkProvider"
            for n in c.body
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        capture = [a.arg for a in methods["_capture_auth_context"].args.args]
        assert capture == ["self", "resolved_cwd", "agent"]
        assert isinstance(methods["_check_auth_readiness"], ast.AsyncFunctionDef)
        assert [a.arg for a in methods["_check_auth_readiness"].args.args] == ["self", "context"]
        assert list(inspect.signature(provider._derive_billing).parameters) == ["context", "status"]
        assert list(inspect.signature(provider._find_claude_cli).parameters) == []
        assert hasattr(provider, "_run_auth_status_subprocess")
        assert provider._FIRST_PARTY_API_PROVIDER == "firstParty"

    def test_pytest_expression_api(self) -> None:
        from _pytest.mark.expression import Expression

        compiled = Expression.compile("real_api")
        assert compiled.evaluate(lambda name, **kw: name == "real_api") is True
        assert compiled.evaluate(lambda name, **kw: False) is False

    def test_console_and_verbosity_hooks_exist(self) -> None:
        import importlib

        run_module = importlib.import_module("conductor.cli.run")
        app_module = importlib.import_module("conductor.cli.app")
        assert hasattr(run_module, "_file_console")
        assert callable(app_module.is_verbose)

    def test_repository_fixtures_and_override_name_exist(self) -> None:
        conftest_names = (
            "_isolate_event_log_root",
            "_isolate_run_records_root",
            "_isolated_runs_dir",
            "_stub_claude_auth_readiness",
        )
        assert missing_module_level_fixtures(ROOT_CONFTEST.read_text(), conftest_names) == []
        assert "pytest_collection_modifyitems" in module_level_functions(
            ast.parse(ROOT_CONFTEST.read_text())
        )
        live_source = LIVE_MODULE.read_text()
        # The same-name override and the zero-skip registration are module-level fixtures.
        assert (
            missing_module_level_fixtures(
                live_source, ("_stub_claude_auth_readiness", "_register_zero_skip_reporter")
            )
            == []
        )
        assert set(lm.SANDBOX_EXPORTS) <= set(dir(lm))

    def test_production_path_signatures_used_by_the_real_adapters(self) -> None:
        pytest.importorskip("claude_agent_sdk")
        from conductor.billing import SUBSCRIPTION_LABEL, AggregateBilling
        from conductor.cli.run import display_usage_summary
        from conductor.config.loader import load_config
        from conductor.engine.workflow import WorkflowEngine
        from conductor.events import WorkflowEvent, WorkflowEventEmitter
        from conductor.providers.factory import create_provider
        from conductor.providers.registry import ProviderRegistry

        assert inspect.iscoroutinefunction(create_provider)
        assert {
            "provider_type",
            "validate",
            "default_model",
            "max_session_seconds",
            "provider_settings",
        } <= set(inspect.signature(create_provider).parameters)
        engine_params = inspect.signature(WorkflowEngine.__init__).parameters
        assert {"config", "registry", "event_emitter", "workflow_path"} <= set(engine_params)
        assert inspect.iscoroutinefunction(WorkflowEngine.run)
        assert list(inspect.signature(WorkflowEngine.run).parameters) == ["self", "inputs"]
        assert callable(WorkflowEngine.get_execution_summary)
        assert list(inspect.signature(display_usage_summary).parameters) == [
            "usage_data",
            "console",
        ]
        assert list(inspect.signature(load_config).parameters) == ["path"]
        assert callable(WorkflowEventEmitter.subscribe) and callable(WorkflowEvent.to_dict)
        assert callable(AggregateBilling.from_wire)
        assert inspect.iscoroutinefunction(ProviderRegistry.__aenter__)
        assert inspect.iscoroutinefunction(ProviderRegistry.__aexit__)
        assert SUBSCRIPTION_LABEL == "API-equivalent estimate"

    def test_the_sdk_client_method_the_observer_wraps_exists(self) -> None:
        pytest.importorskip("claude_agent_sdk")
        import claude_agent_sdk

        method = claude_agent_sdk.ClaudeSDKClient.__dict__["receive_response"]
        assert inspect.isasyncgenfunction(method) or inspect.iscoroutinefunction(method)

    def test_assistant_error_literals_match_the_sdk(self) -> None:
        pytest.importorskip("claude_agent_sdk")
        import typing

        from claude_agent_sdk.types import AssistantMessageError

        assert set(typing.get_args(AssistantMessageError)) == set(lm.ASSISTANT_ERRORS)

    def test_result_message_carries_the_typed_status_field(self) -> None:
        pytest.importorskip("claude_agent_sdk")
        import dataclasses

        from claude_agent_sdk.types import AssistantMessage, ResultMessage

        assert "api_error_status" in {f.name for f in dataclasses.fields(ResultMessage)}
        assert "error" in {f.name for f in dataclasses.fields(AssistantMessage)}

    def test_every_live_test_is_covered_by_the_marker_and_env_gate(self) -> None:
        tree = module_ast()
        marks = next(
            n.value
            for n in tree.body
            if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "pytestmark"
        )
        marks_src = ast.unparse(marks)
        assert "pytest.mark.real_api" in marks_src
        assert "skipif" in marks_src and "CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION" in marks_src
        names = {
            n.name
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
        }
        assert names == {"test_official_live_evidence", "test_readiness_probe_only"}
        assert [m.mark.name for m in lm.pytestmark if hasattr(m, "mark")] == ["real_api", "skipif"]

    def test_no_login_or_logout_argument_anywhere(self) -> None:
        for node in ast.walk(module_ast()):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value.strip().lower() not in {"login", "logout", "auth"}, node.value

    def test_no_pytest_skip_is_used_for_cases(self) -> None:
        for node in ast.walk(module_ast()):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"skip", "importorskip", "xfail"}, node.attr

    def test_lazy_sdk_import(self) -> None:
        for node in module_ast().body:
            if isinstance(node, ast.Import):
                assert all(a.name != "claude_agent_sdk" for a in node.names)
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("claude_agent_sdk")

    def test_no_root_logger_or_pytest_log_capture_is_touched(self) -> None:
        """H12 / H21: the harness never uses ``caplog``, never changes the root logger."""
        tree = module_ast()
        assert "caplog" not in {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert not {"at_level", "basicConfig", "root", "set_level"} & attributes
        calls = [
            c
            for c in ast.walk(tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute)
            and c.func.attr == "getLogger"
        ]
        assert [ast.unparse(c) for c in calls] == ["logging.getLogger(name)"]  # never the root
        holders = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
            for ref in ast.walk(node)
            if isinstance(ref, ast.Attribute) and ref.attr in {"setLevel", "propagate", "disabled"}
        }
        assert holders == {"PrivateLogCapture"}  # logger state changes live in one class
        assert lm.PRIVATE_LOGGERS == ("claude_agent_sdk", "conductor.providers.claude_agent_sdk")

    def test_no_live_test_requests_both_capture_fixtures_or_log_capture(self) -> None:
        for node in module_ast().body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                params = {a.arg for a in node.args.args}
                assert not {"capfd", "capsys"} <= params, node.name
                assert "caplog" not in params, node.name

    def test_no_signal_is_sent_to_a_discovered_pid(self) -> None:
        """``os.kill*`` appears only in the helper that owns its own process group."""
        holders: set[str] = set()
        for func in ast.walk(module_ast()):
            if isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                for node in ast.walk(func):
                    if isinstance(node, ast.Attribute) and node.attr in {
                        "kill",
                        "killpg",
                        "terminate",
                    }:
                        holders.add(func.name)
        assert holders == {"_run_owned_subprocess"}


class TestModuleShape:
    @staticmethod
    def _first_statements(name: str) -> list[str]:
        for node in module_ast().body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
                body = list(node.body)
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    body = body[1:]
                return [ast.unparse(s) for s in body[:2]]
        raise AssertionError(name)

    @pytest.mark.parametrize("name", list(lm.iter_public_process_helpers()))
    def test_every_process_capable_helper_starts_with_gate_and_isolation(self, name: str) -> None:
        assert self._first_statements(name) == [
            "require_live_optin(config)",
            "assert_live_isolation(tmp_path)",
        ]

    def test_helpers_take_config_and_tmp_path(self) -> None:
        for name in lm.iter_public_process_helpers():
            params = list(inspect.signature(getattr(lm, name)).parameters)
            assert params[:2] == ["config", "tmp_path"], name


# ============================================================================
# H13: example pin
# ============================================================================


def _walk_keys(node: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            keys.add(str(key))
            keys |= _walk_keys(value)
    elif isinstance(node, list):
        for value in node:
            keys |= _walk_keys(value)
    return keys


def example_problems(raw: dict[str, Any]) -> list[str]:
    """Every way a document departs from the design's required example structure."""
    problems: list[str] = []
    workflow = raw.get("workflow", {})
    runtime = workflow.get("runtime", {})
    provider = runtime.get("provider", {})
    agents = raw.get("agents", [])
    if provider.get("name") != "claude-agent-sdk":
        problems.append("provider")
    if provider.get("auth_mode") != "subscription":
        problems.append("auth_mode")
    if provider.get("native_tools") != "none":
        problems.append("native_tools")
    if provider.get("setting_sources") not in ([], None):
        problems.append("setting_sources")
    if not isinstance(runtime.get("max_session_seconds"), int | float) or not (
        0 < runtime["max_session_seconds"] <= 60
    ):
        problems.append("max_session_seconds")
    if not str(runtime.get("default_model", "")).startswith("claude-haiku"):
        problems.append("default_model")
    if len(agents) != 1 or agents[0].get("name") != "answerer":
        problems.append("agents")
    elif agents[0].get("tools") != []:
        problems.append("tools")
    elif "answer" not in agents[0].get("output", {}):
        problems.append("output")
    if "retry" in _walk_keys(raw):
        problems.append("retry")
    question = workflow.get("input", {}).get("question", {})
    if "default" not in question:
        problems.append("input_default")
    return problems


class TestExamplePin:
    example = REPO_ROOT / "examples" / "claude-agent-sdk-subscription.yaml"

    def _raw(self) -> dict[str, Any]:
        import yaml

        return yaml.safe_load(self.example.read_text())

    def test_intended_policy_entry_exists(self) -> None:
        from tests.test_integration.test_examples import TestClaudeAgentSdkExamplesNativeTools

        intended = TestClaudeAgentSdkExamplesNativeTools._INTENDED
        assert intended["claude-agent-sdk-subscription.yaml"] == ("none", {"answerer": "none"})

    def test_document_has_exactly_the_required_structure(self) -> None:
        assert example_problems(self._raw()) == []

    def test_loaded_configuration(self) -> None:
        from conductor.config.loader import load_config
        from conductor.config.schema import AgentDef
        from conductor.config.validator import validate_workflow_config

        config = load_config(self.example)
        validate_workflow_config(config, workflow_path=self.example)
        provider = config.workflow.runtime.provider
        assert provider.auth_mode == "subscription"
        assert provider.native_tools == "none"
        assert not provider.setting_sources
        agent = config.agents[0]
        assert isinstance(agent, AgentDef)
        assert agent.tools == []
        assert config.workflow.runtime.max_session_seconds == 60
        assert config.workflow.runtime.default_model == "claude-haiku-4-5"
        assert agent.output is not None and "answer" in agent.output

    def test_retry_default_cannot_multiply_attempts(self) -> None:
        from conductor.config.schema import RetryPolicy

        assert RetryPolicy().max_attempts == 1

    @pytest.mark.parametrize(
        ("mutation", "expected"),
        [
            (lambda d: d["workflow"]["runtime"]["provider"].update(auth_mode="auto"), "auth_mode"),
            (
                lambda d: d["workflow"]["runtime"]["provider"].update(native_tools="all"),
                "native_tools",
            ),
            (
                lambda d: d["workflow"]["runtime"]["provider"].update(setting_sources=["user"]),
                "setting_sources",
            ),
            (lambda d: d["workflow"]["runtime"].pop("max_session_seconds"), "max_session_seconds"),
            (
                lambda d: d["workflow"]["runtime"].update(max_session_seconds=3600),
                "max_session_seconds",
            ),
            (lambda d: d["agents"][0].pop("tools"), "tools"),
            (lambda d: d["agents"][0].update(retry={"max_attempts": 3}), "retry"),
            (
                lambda d: d["workflow"]["runtime"].update(default_model="claude-opus-9"),
                "default_model",
            ),
            (lambda d: d["agents"][0].update(output={}), "output"),
        ],
        ids=[
            "auto",
            "native-tools",
            "setting-sources",
            "no-session-bound",
            "unbounded-session",
            "no-tools",
            "retry",
            "model",
            "no-output",
        ],
    )
    def test_checker_catches_mutations(
        self, mutation: Callable[[dict[str, Any]], object], expected: str
    ) -> None:
        raw = self._raw()
        mutation(raw)
        assert expected in example_problems(raw)

    def test_l3_variant_differs_only_in_auth_mode_and_validates(self) -> None:
        import yaml

        from conductor.config.loader import load_config_string

        variants = lm.build_variants(self.example.read_text(), CANARY, {})
        assert lm.config_diff_paths(variants[S.L3].config, self._raw()) == [
            "workflow.runtime.provider.auth_mode"
        ]
        assert lm.config_diff_paths(variants[S.L2].config, self._raw()) == []
        for case in (S.L3, S.L2):
            config = load_config_string(yaml.safe_dump(dict(variants[case].config)))
            assert config.workflow.runtime.provider.auth_mode == variants[case].auth_mode


# ============================================================================
# H14: runbook reference checker
# ============================================================================


def runbook_references(text: str) -> dict[str, set[str]]:
    """Every checkable reference in a runbook: paths, environment names, selectors, anchors."""
    return {
        "paths": set(re.findall(r"\b((?:examples|docs|tests)/[\w./-]+\.(?:yaml|md|py))", text)),
        "envs": set(re.findall(r"\bCONDUCTOR_REAL_[A-Z_]+\b", text)),
        "selectors": set(re.findall(r"-k\s+([A-Za-z0-9_]+)", text)),
        "anchors": set(re.findall(r"\]\(#([^)]+)\)", text)),
    }


def runbook_reference_problems(text: str, repo_root: Path) -> list[str]:
    """Doc-drift guard: referenced paths, environment names, ``-k`` selectors and anchors exist."""
    problems: list[str] = []
    refs = runbook_references(text)
    for ref in sorted(refs["paths"]):
        if not (repo_root / ref).exists():
            problems.append(f"missing path: {ref}")
    for name in sorted(refs["envs"]):
        if name not in {lm.GATE_ENV, lm.MODEL_ENV}:
            problems.append(f"unknown environment variable: {name}")
    live_tests = [n for n in dir(lm) if n.startswith("test_")]
    for selector in sorted(refs["selectors"]):
        if not any(selector in name for name in live_tests):
            problems.append(f"unknown -k selector: {selector}")
    slugs = {
        re.sub(r"[^a-z0-9 -]", "", h.lower()).strip().replace(" ", "-")
        for h in re.findall(r"^#+\s+(.+)$", text, flags=re.MULTILINE)
    }
    for anchor in sorted(refs["anchors"]):
        if anchor not in slugs:
            problems.append(f"dangling anchor: {anchor}")
    return problems


RUNBOOK_PATH = REPO_ROOT / "docs" / "providers" / "claude-subscription.md"

# Every statement the maintainer section must make (design 13.2.1), as exact text.
REQUIRED_RUNBOOK_STATEMENTS = (
    "experimental",
    "POSIX-only",
    "Never `export` the variable",
    "-m real_api",
    f"{lm.GATE_ENV}=1",
    "the exact value `1`",
    "A human must be present",
    "**never signals**",
    "API-equivalent estimate",
    "not** invoices",
    "makes no such claim",
    "**No live validation has been run yet.**",
    "readiness-only check",
    "official live validation",
    "optional manual example",
    "clean committed tree",
    "Untracked files make the tree dirty",
    "tested Git SHA",
    "`git_sha`",
    "not official end-to-end evidence",
    "set -o pipefail",
    'tee "$EVIDENCE_FILE"',
    "outside the repository",
    "--show-capture=no",
    "--disable-warnings",
    "--tb=no",
    "-rN",
    "--color=no",
    "-p no:cacheprovider",
    "before changing any documentation claim",
    "later commit",
    # sanitized rendering, cancellation and the record fields (design 13.2.1 items 9-11)
    "gate-scoped report sanitizer",
    "are **not saved**",
    "only fixed framework markers and validated `EVIDENCE` records",
    "original exception, the exit status and the control flow are untouched",
    "prereq_report_sanitizer_unavailable",
    "`pipefail` keeps a failing exit status",
    "remains the primary outcome",
    "`cleanup_failed`",
    "`exception_class`",
    "`evidence_fallback_failed: <case>`",
    "production cleanup exception",
    # the discard rule, the candidate rule and the interrupt lines (items 12-14)
    "A saved file **without the evidence section must be deleted**",
    "must **not be shared, committed, quoted as evidence or used to authorize the next live step**",
    "necessary, never sufficient",
    "A capture is never judged by eye",
    "`conftest` import failure or a plugin-load failure",
    "`prereq_terminalreporter_missing`",
    "failure to register the evidence plugin",
    "registration window",
    "exactly three lines",
    "`(to show a full traceback on KeyboardInterrupt use --full-trace)`",
    "**No other interrupt line is acceptable**",
    "`PYTEST_DISABLE_PLUGIN_AUTOLOAD` is deliberately **not**",
    "seven unset operations",
    "rerun the offline safety tests before any live validation",
    # the shell gate (items 13 and 15)
    "**Bash or Zsh**",
    "**not** generic POSIX `sh`",
    "**plain terminal\nsession**",
    "not accepted",
    "the **pipeline status under `pipefail`, not necessarily pytest's own status**",
    "**very next command**",
    "tests **both** the exit status and the exact\nstdout token",
    "`failure_record`",
    "**kept** locally",
    "**deletes the capture and stops**",
    "leaves **no valid capture**",
    "its own script invocation",
    "`run_record_missing`",
    "`cleanup_failed`",
)


def normalized(text: str) -> str:
    return " ".join(text.split())


def runbook_contract_problems(text: str) -> list[str]:
    """H14 contract: descriptive terms only, every required statement, safe commands, counts."""
    problems: list[str] = []
    flat = normalized(text)
    if re.search(r"\bX[2-5]\b", text):
        problems.append("internal label X<n>")
    if re.search("Pha" + r"se\s+[AB]\b", text):
        problems.append("internal phase label")
    problems.extend(
        f"missing statement: {statement}"
        for statement in REQUIRED_RUNBOOK_STATEMENTS
        if normalized(statement) not in flat
    )
    for command in (lm.READINESS_ONLY_COMMAND, lm.OFFICIAL_COMMAND):
        if command not in text:
            problems.append("a command differs from the authorized form")
    for name in ("PRE_GATE", "CLASSIFY_BLOCK", "MATRIX_BLOCK", "PIPELINE_STATUS_LINE"):
        block = getattr(lm, name).rstrip("\n")
        if "\n" + block not in "\n" + text:  # whole lines: nothing may precede the first one
            problems.append(f"the shell gate block {name} differs from the module's constant")
    if lm.READINESS_ONLY_COMMAND + "\n" + lm.PIPELINE_STATUS_LINE not in text:
        problems.append("the status is not saved as the very next command after the pipeline")
    if "PYTEST_STATUS" in text:
        problems.append("the old status variable name PYTEST_STATUS")
    for block in re.findall(r"```bash\n(.*?)```", text, flags=re.DOTALL):
        tokens = shlex.split(block.replace("\\\n", " "), comments=True)
        problems.extend(
            f"command block uses {bad}" for bad in ("-rA", "-s", "--capture=no") if bad in tokens
        )
        if "real_api" in tokens:
            for flag in lm.EVIDENCE_PYTEST_FLAGS.split() + ["--color=no"]:
                if flag not in tokens:
                    problems.append(f"a live command block lacks {flag}")
            if "PYTEST_DISABLE_PLUGIN_AUTOLOAD" in block:
                problems.append("a live command block sets plugin autoload off")
        if "--check-capture" in tokens:
            hardened = [
                i
                for i in range(1, len(tokens) - 3)
                if tokens[i - 1] == "$PY" and tokens[i : i + 3] == ["-I", "-S", "-B"]
            ]
            if not hardened:
                problems.append("the classifier is not run with -I -S -B")
    if re.search(r"location line[^.]*\b(?:are|is)\s+(?:acceptable|accepted|fine|expected)", flat):
        problems.append("claims pytest's interrupt location line is acceptable output")
    if re.search(r"reaching the (?:gate )?fixture guarantees|guarantees only fixed lines", flat):
        problems.append("claims that reaching the gate fixture guarantees fixed lines")
    if not re.search(r"\*\*one\*\*\s+authentication probe", text):
        problems.append("the readiness-only probe count is not stated as one")
    if not re.search(r"\*\*five\*\*\s+authentication probes", text):
        problems.append("the official probe count is not stated as five")
    if re.search(r"\bthree\b[^.\n]*\bprobes?\b", text, flags=re.IGNORECASE):
        problems.append("a stale three-probe count")
    return problems


class TestRunbookReferences:
    """The pure H14 checker proven on fabricated documents, then applied to the real runbook."""

    def test_good_document_has_no_problems(self) -> None:
        text = (
            "# Runbook\n\n## Live validation\n\nSee [live](#live-validation).\n"
            "`examples/claude-agent-sdk-subscription.yaml` and "
            "`tests/test_integration/test_claude_agent_sdk_subscription_real.py`.\n"
            f"{lm.GATE_ENV}=1 pytest -m real_api x -k official_live_evidence\n"
            f"{lm.MODEL_ENV}=claude-haiku-4-5 -k readiness_probe_only\n"
        )
        assert runbook_reference_problems(text, REPO_ROOT) == []

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("see examples/does-not-exist.yaml", "missing path"),
            ("CONDUCTOR_REAL_CLAUDE_TYPO=1", "unknown environment variable"),
            ("pytest -k no_such_live_test", "unknown -k selector"),
            ("[x](#not-a-heading)\n# Other", "dangling anchor"),
            ("docs/providers/no-such-page.md", "missing path"),
        ],
    )
    def test_drift_is_detected(self, text: str, expected: str) -> None:
        problems = runbook_reference_problems(text, REPO_ROOT)
        assert any(expected in p for p in problems), problems

    def test_environment_names_match_the_module_constants(self) -> None:
        assert lm.GATE_ENV == "CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION"
        assert lm.MODEL_ENV == "CONDUCTOR_REAL_CLAUDE_MODEL"
        assert lm.EXAMPLE_PATH.is_file()

    # -- H14 applied to the REAL runbook ---------------------------------------------------
    def test_h14_the_real_runbook_has_no_drifting_reference(self) -> None:
        assert RUNBOOK_PATH.is_file()
        text = RUNBOOK_PATH.read_text()
        assert runbook_reference_problems(text, REPO_ROOT) == []

    def test_h14_the_checker_actually_examined_the_real_runbook(self) -> None:
        refs = runbook_references(RUNBOOK_PATH.read_text())
        assert {
            "examples/claude-agent-sdk-subscription.yaml",
            "tests/test_integration/test_claude_agent_sdk_subscription_real.py",
            "tests/test_config/test_claude_subscription_real_gate.py",
        } <= refs["paths"]
        assert refs["envs"] == {lm.GATE_ENV}
        assert refs["selectors"] == {"readiness_probe_only", "official_live_evidence"}
        assert {"status-table", "run-the-minimal-example"} <= refs["anchors"]

    def test_h14_the_real_runbook_is_about_this_module(self) -> None:
        """The runbook names the exact test selectors that exist in the live module."""
        for selector in runbook_references(RUNBOOK_PATH.read_text())["selectors"]:
            assert f"test_{selector}" in dir(lm)

    def test_the_real_runbook_satisfies_the_contract(self) -> None:
        text = RUNBOOK_PATH.read_text()
        assert runbook_contract_problems(text) == []
        assert text.count("*not yet*") >= 6  # every live-proven cell still reads "not yet"
        assert "No live validation has been run yet" in text

    def test_the_runbook_commands_are_the_modules_authorized_commands(self) -> None:
        text = RUNBOOK_PATH.read_text()
        assert lm.READINESS_ONLY_COMMAND in text and lm.OFFICIAL_COMMAND in text
        assert lm.PIPEFAIL_LINE in text
        assert text.index(lm.PIPEFAIL_LINE) < text.index(lm.READINESS_ONLY_COMMAND)

    @pytest.mark.parametrize(
        ("old", "new", "expected"),
        [
            ("readiness-only check", "X" + "2", "internal label"),
            ("official live validation", "X" + "3", "internal label"),
            ("readiness-only check", "X" + "4", "internal label"),
            ("optional manual example", "X" + "5", "internal label"),
            (
                "## Before either operation",
                "## " + "Phase " + "B: before either operation",
                "phase label",
            ),
            ("## Before either operation", "## Phase " + "A: before", "phase label"),
            ("clean committed tree", "tree", "missing statement: clean committed tree"),
            (
                "Untracked files make the tree dirty",
                "Files may exist",
                "missing statement: Untracked files",
            ),
            ("tested Git SHA", "tested revision", "missing statement: tested Git SHA"),
            ("`git_sha`", "the SHA", "missing statement: `git_sha`"),
            (
                "not official end-to-end evidence",
                "official evidence",
                "missing statement: not official",
            ),
            ("set -o pipefail", "set -o nounset", "differs from the module"),
            ('2>&1 | tee "$EVIDENCE_FILE"', "2>&1", "differs from the authorized"),
            ("--tb=no -rN -p no:cacheprovider", "--tb=no -rA -p no:cacheprovider", "-rA"),
            ("--disable-warnings --tb=no", "--tb=no", "lacks --disable-warnings"),
            ("--tb=no -rN", "-rN", "lacks --tb=no"),
            ("-q --color=no", "--color=no", "lacks -q"),
            ("--color=no --show-capture=no", "--show-capture=no", "lacks --color=no"),
            ("-I -S -B", "-I -S", "not run with -I -S -B"),
            ("PIPELINE_STATUS=$?", "PYTEST_" + "STATUS=$?", "PYTEST_" + "STATUS"),
            (': "${EXPECTED:?}"', ': "${EXPECTED}"', "differs from the module"),
            (
                "gate-scoped report sanitizer",
                "report filter",
                "missing statement: gate-scoped report sanitizer",
            ),
            ("are **not saved**", "may be saved", "missing statement: are **not saved**"),
            (
                "prereq_report_sanitizer_unavailable",
                "a failure",
                "missing statement: prereq_report_sanitizer_unavailable",
            ),
            (
                "`pipefail` keeps a failing exit status",
                "`pipefail` is nice",
                "missing statement: `pipefail` keeps",
            ),
            (
                "remains the primary outcome",
                "is replaced",
                "missing statement: remains the primary",
            ),
            ("`cleanup_failed`", "the cleanup field", "missing statement: `cleanup_failed`"),
            ("`exception_class`", "the class field", "missing statement: `exception_class`"),
            (
                "production cleanup exception",
                "library error",
                "missing statement: production cleanup exception",
            ),
            (
                "**Cancellation.**",
                "pytest's interrupt banner and location line are acceptable output. "
                "**Cancellation.**",
                "location line",
            ),
            ("-q --color=no", "-q -s --color=no", "command block uses -s"),
            ("**five** authentication probes", "**three** authentication probes", "five"),
            ("**one**\n  authentication probe", "**two** authentication probe", "one"),
            ("outside the repository", "somewhere", "missing statement: outside"),
            ("before changing any documentation claim", "afterwards", "missing statement: before"),
            ("A human must be present", "A person helps", "missing statement: A human"),
            ("**Bash or Zsh**", "a shell", "missing statement: **Bash or Zsh**"),
            ("plain terminal", "terminal", "missing statement: **plain terminal"),
            ("exactly three lines", "exactly two lines", "missing statement: exactly three lines"),
            (
                "**No other interrupt line is acceptable**",
                "Other lines are fine",
                "missing statement: **No other",
            ),
            (
                "A saved file **without the evidence section must be deleted**",
                "A saved file is fine",
                "missing statement: A saved file",
            ),
            ("necessary, never sufficient", "enough", "missing statement: necessary"),
            (
                "A capture is never judged by eye",
                "Judge a capture by eye",
                "missing statement: A capture is never",
            ),
            ("**kept** locally", "shared", "missing statement: **kept** locally"),
            (
                "leaves **no valid capture**",
                "is fine",
                "missing statement: leaves **no valid",
            ),
            (
                "**deletes the capture and stops**",
                "continues",
                "missing statement: **deletes",
            ),
            ("its own script invocation", "one script", "missing statement: its own script"),
            ("rerun the offline safety tests", "skip tests", "missing statement: rerun"),
            (
                "`PYTEST_DISABLE_PLUGIN_AUTOLOAD` is deliberately **not**",
                "plugins are off",
                "missing statement: `PYTEST_DISABLE",
            ),
        ],
    )
    def test_h14_contract_drift_is_detected(self, old: str, new: str, expected: str) -> None:
        text = RUNBOOK_PATH.read_text()
        # every occurrence, whatever the line wrapping: one mention is not the contract
        pattern = r"\s+".join(re.escape(word) for word in old.split())
        drifted = re.sub(pattern, lambda _match: new, text)
        assert drifted != text, old
        problems = runbook_contract_problems(drifted)
        assert any(expected in problem for problem in problems), (old, problems)

    def test_the_contract_checker_accepts_only_a_complete_document(self) -> None:
        assert runbook_contract_problems("") != []
        assert runbook_contract_problems("readiness-only check") != []

    def test_the_runbook_does_not_name_the_retired_streams(self) -> None:
        text = RUNBOOK_PATH.read_text()
        for retired in ("capfd", "capsys", "caplog", "raw_response"):
            assert retired not in text, retired
        for stream in lm.REQUIRED_STREAMS:
            assert f"`{stream}`" in text, stream

    def test_the_runbook_does_not_overclaim_or_install(self) -> None:
        text = RUNBOOK_PATH.read_text()
        lowered = text.lower()
        assert not re.search(r"^usage:", text, flags=re.MULTILINE)  # no unlabelled sample output
        assert "make test" not in lowered
        assert not re.search(r"^\s*(?:\$\s*)?make\s+\w+", text, flags=re.MULTILINE)
        assert "mutation" not in lowered  # mutation results are not maintained evidence
        assert not re.search(r"\bM\d{1,2}\b", text)
        assert "validated the" not in lowered and "has succeeded" not in lowered
        for installer in ("uv sync", "uv run ", "pip install", "npm install -g claude"):
            assert installer not in text.replace("Install with: npm install -g @anthropic-ai", "")
        assert "export CONDUCTOR" not in text
        assert "384 passed" not in text and "384 passed" not in LIVE_MODULE.read_text()
        assert not re.search(
            r"\b\d{3,5} passed, \d+ skipped\b", text
        )  # no fixed test-count baseline

    def test_the_runbook_status_table_separates_the_four_states(self) -> None:
        header = next(
            line
            for line in RUNBOOK_PATH.read_text().splitlines()
            if line.startswith("| Capability")
        )
        assert [c.strip() for c in header.strip("|").split("|")] == [
            "Capability",
            "Implemented",
            "Hermetically tested",
            "Live-proven",
            "Unverified",
        ]


# ============================================================================
# H15: descendants (report only)
# ============================================================================

PS_OUTPUT = """\
  PID  PPID COMM
    1     0 /sbin/launchd
  100     1 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  200   100 node
  300   200 sh -c weird
  400     1 python3
  500   400 ps
garbage line
"""


class FakePopen:
    def __init__(self, output: str = "", *, pid: int = 500, timeouts: int = 0) -> None:
        self.pid = pid
        self.output = output
        self.timeouts = timeouts
        self.returncode = 0
        self.communicate_calls = 0

    def __call__(self, *args: object, **kwargs: object) -> FakePopen:
        self.kwargs = kwargs
        self.args = args
        return self

    def communicate(self, timeout: float | None = None) -> tuple[str, None]:
        self.communicate_calls += 1
        if self.timeouts:
            self.timeouts -= 1
            raise subprocess.TimeoutExpired("ps", timeout or 0)
        return self.output, None


def no_signals(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("a signal was sent")

    monkeypatch.setattr(os, "kill", boom)
    monkeypatch.setattr(os, "killpg", boom)
    return monkeypatch


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps = 0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps += 1
        self.now += seconds


def scripted_reader(
    *tables: dict[int, tuple[int, str]],
) -> Callable[[], dict[int, tuple[int, str]]]:
    calls = {"n": 0}

    def read() -> dict[int, tuple[int, str]]:
        table = tables[min(calls["n"], len(tables) - 1)]
        calls["n"] += 1
        return table

    read.calls = calls  # type: ignore[attr-defined]
    return read


class TestDescendants:
    ROOT = 4242

    def test_parse_ps_handles_macos_and_linux_rows_and_drops_the_ps_child(self) -> None:
        table = lm.parse_ps(PS_OUTPUT, ps_pid=500)
        assert 500 not in table
        assert table[100] == (1, "Google?Chrome")
        assert table[300] == (200, "sh?-c?weird")
        assert table[1] == (0, "launchd")
        assert "garbage" not in str(table)
        assert 500 in lm.parse_ps(PS_OUTPUT)  # not dropped when no owned pid is given
        linux = lm.parse_ps("    7     1 bash\n", ps_pid=None)
        assert linux == {7: (1, "bash")}

    def test_short_name_is_bounded_and_sanitized(self) -> None:
        assert len(lm.short_name("/usr/bin/" + "x" * 100)) == 32
        assert lm.short_name("we ird$name") == "we?ird?name"
        assert lm.short_name("   ") == "?"

    def test_transitive_descendants_exclude_the_root(self) -> None:
        table = {100: (1, "a"), 200: (100, "b"), 300: (200, "c"), 400: (1, "d"), 1: (0, "init")}
        assert lm.descendants(table, 100) == {200, 300}
        assert lm.descendants(table, 1) == {100, 200, 300, 400}
        assert lm.descendants(table, 999) == set()
        cyc = {5: (6, "a"), 6: (5, "b")}
        assert lm.descendants(cyc, 5) == {6}

    def test_owned_ps_child_is_excluded_by_popen_pid(self) -> None:
        popen = FakePopen(PS_OUTPUT, pid=500)
        table = lm.read_ps_table(popen=popen)
        assert 500 not in table and 400 in table
        assert popen.kwargs["start_new_session"] is True

    def test_missing_ps_is_a_fixed_failure(self) -> None:
        def missing(*a: object, **k: object) -> None:
            raise FileNotFoundError("ps")

        with raises_outcome(lm.Outcome.PREREQ_PS_MISSING):
            lm.read_ps_table(popen=missing)

    def test_ps_timeout_kills_only_its_own_group(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sent: list[tuple[int, int]] = []
        monkeypatch.setattr(os, "killpg", lambda pgid, sig: sent.append((pgid, sig)))
        popen = FakePopen(PS_OUTPUT, pid=777, timeouts=1)
        with raises_outcome(lm.Outcome.PREREQ_PS_MISSING):
            lm.read_ps_table(popen=popen)
        import signal

        assert sent == [(777, signal.SIGKILL)]

    async def test_exit_within_grace_reports_no_descendants(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock()
        child = {self.ROOT + 1: (self.ROOT, "node")}
        read = scripted_reader(child, child, {}, {})
        with monkeypatch.context() as scoped:
            no_signals(scoped)
            report = await lm.observe_descendants(
                read, self.ROOT, frozenset(), clock=clock, sleep=clock.sleep
            )
        assert report.verdict is lm.Outcome.NO_DESCENDANTS_REMAINING
        assert report.remaining == []
        assert clock.sleeps == 2  # natural grace: polled, never signalled

    async def test_persisting_descendant_is_a_leak_with_sanitized_report(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock()
        child = {self.ROOT + 1: (self.ROOT, "we ird"), self.ROOT + 2: (self.ROOT + 1, "grand")}
        with monkeypatch.context() as scoped:
            no_signals(scoped)
            report = await lm.observe_descendants(
                scripted_reader(child), self.ROOT, frozenset(), clock=clock, sleep=clock.sleep
            )
        assert report.verdict is lm.Outcome.DESCENDANT_LEAK
        assert report.remaining == [
            {"pid": self.ROOT + 1, "name": "we ird"},
            {"pid": self.ROOT + 2, "name": "grand"},
        ]
        assert clock.sleeps == 40  # 10 s grace at 0.25 s
        lm.evidence(
            descendants=report.verdict,
            descendant_report=[
                {"pid": r["pid"], "name": lm.short_name(str(r["name"]))} for r in report.remaining
            ],
        )

    async def test_final_observation_catches_a_late_descendant(self) -> None:
        clock = Clock()
        late = {self.ROOT + 9: (self.ROOT, "late")}
        report = await lm.observe_descendants(
            scripted_reader({}, late), self.ROOT, frozenset(), clock=clock, sleep=clock.sleep
        )
        assert report.verdict is lm.Outcome.DESCENDANT_LEAK

    async def test_before_set_is_not_reported(self) -> None:
        clock = Clock()
        table = {self.ROOT + 1: (self.ROOT, "old")}
        report = await lm.observe_descendants(
            scripted_reader(table),
            self.ROOT,
            frozenset({self.ROOT + 1}),
            clock=clock,
            sleep=clock.sleep,
        )
        assert report.verdict is lm.Outcome.NO_DESCENDANTS_REMAINING

    def test_disclaimer_names_orphans_and_pid_reuse(self) -> None:
        assert "orphan" in lm.DESCENDANT_DISCLAIMER and "PID reuse" in lm.DESCENDANT_DISCLAIMER
        report = lm.DescendantReport(lm.Outcome.NO_DESCENDANTS_REMAINING, [])
        assert "not proof" in report.disclaimer

    async def test_wrapper_records_a_leak_and_passes_the_runner_result_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock()
        leaked = {self.ROOT + 1: (self.ROOT, "leaky")}
        state = {"leaked": False}

        def read() -> dict[int, tuple[int, str]]:
            return leaked if state["leaked"] else {}

        failure = RuntimeError("case failed too")

        async def runner(case: lm.Case) -> lm.Outcome:
            state["leaked"] = True
            raise failure

        board = lm.FindingsBoard()
        wrapped = lm.with_descendant_check(
            runner, read_table=read, root_pid=self.ROOT, board=board, clock=clock, sleep=clock.sleep
        )
        with monkeypatch.context() as scoped:
            no_signals(scoped)
            with pytest.raises(RuntimeError) as info:
                await wrapped(lm.Case.L1)
        assert info.value is failure  # the runner's own exception, unchanged
        findings = board.for_case(lm.Case.L1)
        assert findings.descendant_leak
        assert findings.descendant_report == [{"pid": self.ROOT + 1, "name": "leaky"}]

    async def test_the_case_wrapper_turns_a_recorded_leak_into_the_primary_outcome(self) -> None:
        clock = Clock()
        state = {"leaked": False}

        def read() -> dict[int, tuple[int, str]]:
            return {self.ROOT + 1: (self.ROOT, "leaky")} if state["leaked"] else {}

        async def runner(case: lm.Case) -> lm.Outcome:
            state["leaked"] = True
            raise RuntimeError("case failed too")

        board = lm.FindingsBoard()
        wrapped = lm.with_descendant_check(
            runner, read_table=read, root_pid=self.ROOT, board=board, clock=clock, sleep=clock.sleep
        )
        records: list[dict[str, object]] = []
        result = await lm.run_ordered_cases(
            {lm.Case.L1: wrapped},
            quota=lm.QuotaCounter(),
            emit=records.append,
            cases=(lm.Case.L1,),
            board=board,
        )
        assert result.results[0].outcome is lm.Outcome.DESCENDANT_LEAK
        assert result.results[0].adapter_outcome is lm.Outcome.CASE_FAILED
        assert records[0]["descendant_report"] == [{"pid": self.ROOT + 1, "name": "leaky"}]

    async def test_wrapper_preserves_the_runner_error_and_records_clean_verdict(self) -> None:
        clock = Clock()

        async def failing(case: lm.Case) -> lm.Outcome:
            raise ValueError("kept")

        async def fine(case: lm.Case) -> lm.Outcome:
            return lm.Outcome.OK

        board = lm.FindingsBoard()
        kwargs: dict[str, Any] = {
            "read_table": lambda: {},
            "root_pid": self.ROOT,
            "clock": clock,
            "sleep": clock.sleep,
            "board": board,
        }
        with pytest.raises(ValueError, match="kept"):
            await lm.with_descendant_check(failing, **kwargs)(lm.Case.L1)
        assert board.for_case(lm.Case.L1).descendants is lm.Outcome.NO_DESCENDANTS_REMAINING
        assert await lm.with_descendant_check(fine, **kwargs)(lm.Case.L3) is lm.Outcome.OK
        assert board.for_case(lm.Case.L3).descendants is lm.Outcome.NO_DESCENDANTS_REMAINING

    def test_positive_control_real_ps_sees_an_owned_child(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The test creates, observes and cleans up its own child; the checker never signals."""
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            deadline = time.monotonic() + 10
            seen: set[int] = set()
            table: lm.PsTable = {}
            while time.monotonic() < deadline and child.pid not in seen:
                with monkeypatch.context() as scoped:  # scoped: not covering the cleanup below
                    no_signals(scoped)
                    table = lm.read_ps_table()
                    seen = lm.descendants(table, os.getpid())
                time.sleep(0.05)
            assert child.pid in seen
            assert all(name != "ps" for pid, (ppid, name) in table.items() if ppid == os.getpid())
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


# ============================================================================
# H18 / H19 / H20: cancellation, precedence and canary_scan, through the case wrapper
# ============================================================================

ROOT_PID = 4242


class OtherInterrupt(BaseException):
    """A ``BaseException`` that is neither ``KeyboardInterrupt`` nor ``CancelledError``."""


class Driven:
    """One run of the real case wrapper, descendant check and findings ledger, with fakes."""

    def __init__(self) -> None:
        self.called: list[lm.Case] = []
        self.records: list[dict[str, object]] = []
        self.marks: list[str] = []
        self.result: lm.SessionResult | None = None
        self.raised: BaseException | None = None
        self.board = lm.FindingsBoard(CANARY)

    def case_records(self) -> list[dict[str, object]]:
        return [r for r in self.records if "case" in r]

    def run_level(self) -> dict[str, object]:
        return next(r for r in self.records if "case" not in r)


def drive(
    script: object,
    *,
    cases: Sequence[lm.Case] = (S.L1,),
    canary_in: str | None = None,
    incomplete: bool = False,
    descendant: bool = False,
    observation_error: bool = False,
    emit_error: bool = False,
    assembly_error: bool = False,
    emit_fails: Callable[[dict[str, object]], bool] | None = None,
    mark: Callable[[str], None] | None = None,
) -> Driven:
    """Run ``script`` (an outcome, or an exception the runner raises) through the wrappers."""
    out = Driven()
    clock = Clock()
    table: dict[int, tuple[int, str]] = {}

    async def runner(case: lm.Case) -> Any:
        out.called.append(case)
        streams = clean_streams()
        if canary_in is not None:
            streams[canary_in] = f"leaked {CANARY}"
        if incomplete:
            del streams["events"]
        out.board.for_case(case).record_streams(CANARY, streams)
        if descendant:
            table[ROOT_PID + 1] = (ROOT_PID, "leaky")
        if isinstance(script, BaseException):
            raise script
        return script

    def read() -> dict[int, tuple[int, str]]:
        if observation_error and out.called:
            raise RuntimeError("process table unreadable")
        return dict(table)

    def emit(record: dict[str, object]) -> None:
        if emit_error and "case" in record:
            raise RuntimeError("emit failed")
        if emit_fails is not None and emit_fails(record):
            raise RuntimeError("PLANTED-emit-4417")
        out.records.append(record)

    ticks = {"n": 0}

    def case_clock() -> float:
        ticks["n"] += 1
        if assembly_error and ticks["n"] >= 2:  # the case record is assembled after the case
            raise RuntimeError("PLANTED-assembly-4417")
        return float(ticks["n"])

    wrapped = lm.with_descendant_check(
        runner,
        read_table=read,
        root_pid=ROOT_PID,
        board=out.board,
        clock=clock,
        sleep=clock.sleep,
        grace_s=0.0,
    )

    async def go() -> lm.SessionResult:
        return await lm.run_ordered_cases(
            dict.fromkeys(cases, wrapped),
            quota=lm.QuotaCounter(),
            emit=emit,
            cases=cases,
            board=out.board,
            clock=case_clock,
            mark=mark if mark is not None else out.marks.append,
        )

    try:
        out.result = asyncio.run(go())
    except BaseException as exc:
        if not (isinstance(script, BaseException) and exc is script):
            raise  # only the planted exception is expected
        out.raised = exc
    return out


def assert_preserved(out: Driven, original: BaseException) -> None:
    """Identity and category: the very same object, and never an ordinary failure."""
    assert out.raised is original
    assert type(out.raised) is type(original)
    assert not isinstance(out.raised, (lm.HarnessFailure, pytest.fail.Exception, AssertionError))
    assert not isinstance(out.raised, Exception) or isinstance(original, Exception)


INTERRUPTS = [
    pytest.param(KeyboardInterrupt, "keyboard_interrupt", id="KeyboardInterrupt"),
    pytest.param(asyncio.CancelledError, "cancelled", id="CancelledError"),
    pytest.param(OtherInterrupt, "other_base_exception", id="other-BaseException"),
]
FINDING_ROWS = [
    pytest.param(None, False, [], id="no-findings"),  # (a) / (c)
    pytest.param("console", False, ["canary_leak"], id="canary"),  # (b) / (d)
    pytest.param(None, True, ["descendant_leak"], id="descendant"),  # (e)
    pytest.param("logs", True, ["canary_leak", "descendant_leak"], id="both"),  # (f)
]


class TestCancellationContract:
    """H18: the original interrupt is primary and is re-raised unchanged."""

    @pytest.mark.parametrize(("factory", "kind"), INTERRUPTS)
    @pytest.mark.parametrize(("canary_in", "descendant", "secondary"), FINDING_ROWS)
    def test_original_exception_object_is_reraised_with_secondary_findings(
        self,
        factory: type[BaseException],
        kind: str,
        canary_in: str | None,
        descendant: bool,
        secondary: list[str],
    ) -> None:
        original = factory()
        out = drive(
            original,
            cases=(S.L1, S.L3, S.L2),
            canary_in=canary_in,
            descendant=descendant,
        )
        assert_preserved(out, original)
        assert out.result is None  # nothing was converted into an ordinary session result
        (record,) = out.case_records()
        assert record["case"] == "L1"
        assert record["outcome"] == "interrupted"
        assert record["adapter_outcome"] == "interrupted"
        assert record["interrupted"] == kind
        assert record["secondary_findings"] == secondary
        expected_scan = [
            f"{name}:{'leak' if name == canary_in else 'clean'}" for name in lm.REQUIRED_STREAMS
        ]
        assert record["canary_scan"] == expected_scan
        assert ("descendants" in record and record["descendants"] == "descendant_leak") == (
            descendant
        )
        assert CANARY not in json.dumps(out.records)
        # no later case runs, and each is recorded as not executed
        assert out.called == [S.L1]
        assert out.run_level()["not_executed"] == (
            "L3:not_executed_after_interrupt,L2:not_executed_after_interrupt"
        )
        assert str(out.run_level()["primary_failure"]).startswith("L1:interrupted:")
        for record in out.records:
            lm.emit_evidence(record)  # every record passes the sanitizer

    def test_the_descendant_check_alone_preserves_the_interrupt(self) -> None:
        original = KeyboardInterrupt()
        clock = Clock()
        board = lm.FindingsBoard(CANARY)
        state = {"leaked": False}

        async def runner(case: lm.Case) -> lm.Outcome:
            state["leaked"] = True
            raise original

        wrapped = lm.with_descendant_check(
            runner,
            read_table=lambda: {ROOT_PID + 1: (ROOT_PID, "x")} if state["leaked"] else {},
            root_pid=ROOT_PID,
            board=board,
            clock=clock,
            sleep=clock.sleep,
            grace_s=0.0,
        )
        with pytest.raises(KeyboardInterrupt) as info:
            asyncio.run(asyncio.wait_for(wrapped(S.L1), 5))
        assert info.value is original
        assert board.for_case(S.L1).descendant_leak  # recorded, not converted

    def test_asyncio_run_lets_keyboard_interrupt_escape_not_an_ordinary_failure(self) -> None:
        """The worst case: a canary and a descendant on top of a Ctrl-C."""
        original = KeyboardInterrupt()
        out = drive(original, canary_in="stdout_stderr", descendant=True)
        assert_preserved(out, original)
        with pytest.raises(KeyboardInterrupt):
            raise out.raised  # type: ignore[misc]

    def test_a_failing_process_table_during_cleanup_does_not_replace_the_interrupt(self) -> None:
        original = asyncio.CancelledError()
        out = drive(original, observation_error=True)
        assert_preserved(out, original)
        (record,) = out.case_records()
        assert record["cleanup_failed"] == ["descendants"]
        assert record["outcome"] == "interrupted"

    def test_a_failing_evidence_emission_does_not_replace_the_interrupt(self) -> None:
        original = KeyboardInterrupt()
        out = drive(original, emit_error=True)
        assert_preserved(out, original)

    def test_an_ordinary_exception_is_still_an_ordinary_failure(self) -> None:
        out = drive(RuntimeError("boom"), cases=(S.L1, S.L3))
        assert out.raised is None and out.result is not None
        assert out.result.results[0].outcome is O.CASE_FAILED
        assert out.result.results[1].outcome is O.NOT_EXECUTED_AFTER_L1_FAILURE
        assert out.case_records()[0]["interrupted"] == "none"

    def test_an_interrupt_before_any_case_state_is_recorded_still_reraises(self) -> None:
        """A pre-hook that is interrupted never starts the case, and is not converted."""
        original = KeyboardInterrupt()

        def hook() -> None:
            raise original

        async def go() -> None:
            await lm.run_ordered_cases(
                {S.L1: Scripted({}, lm.QuotaCounter()).runners()[S.L1]},
                quota=lm.QuotaCounter(),
                emit=lambda r: None,
                cases=(S.L1,),
                pre_hooks={S.L1: hook},
            )

        with pytest.raises(KeyboardInterrupt) as info:
            asyncio.run(go())
        assert info.value is original


# ---------------------------------------------------------------------------
# H32: the cancellation fallback record
# ---------------------------------------------------------------------------

FALLBACK_FIELDS = {
    "case",
    "outcome",
    "adapter_outcome",
    "interrupted",
    "exception_class",
    "cleanup_failed",
    "secondary_findings",
    "canary_scan",
}


def only_marker(out: Driven) -> None:
    assert out.marks == [lm.fallback_failure_marker(S.L1)] == ["evidence_fallback_failed: L1"]
    assert out.case_records() == []  # no record at all: the marker is the only report
    assert "PLANTED" not in json.dumps(out.marks) and "PLANTED" not in json.dumps(out.records)


class TestFallbackEvidence:
    """H32: the record emitted when normal evidence assembly fails during a cancellation."""

    @pytest.mark.parametrize(("factory", "kind"), INTERRUPTS)
    def test_the_fallback_carries_every_required_field(
        self, factory: type[BaseException], kind: str
    ) -> None:
        original = factory()
        out = drive(original, cases=(S.L1, S.L3), assembly_error=True)
        assert_preserved(out, original)
        (record,) = out.case_records()
        assert set(record) == {*FALLBACK_FIELDS, "descendants"}
        assert record["descendants"] == "no_descendants_remaining"
        assert record["case"] == "L1"
        assert record["outcome"] == record["adapter_outcome"] == "interrupted"
        assert record["interrupted"] == kind
        assert record["exception_class"] == type(original).__name__
        assert record["cleanup_failed"] == ["evidence"]
        assert record["secondary_findings"] == []
        assert record["canary_scan"] == [f"{name}:clean" for name in lm.REQUIRED_STREAMS]
        assert len(record["canary_scan"]) == 8  # type: ignore[arg-type]
        assert out.marks == []
        assert out.called == [S.L1]  # no later case runs
        assert out.run_level()["not_executed"] == "L3:not_executed_after_interrupt"
        assert "PLANTED" not in json.dumps(out.records)

    @pytest.mark.parametrize(("factory", "kind"), INTERRUPTS)
    @pytest.mark.parametrize(("canary_in", "descendant", "secondary"), FINDING_ROWS)
    def test_no_finding_is_lost(
        self,
        factory: type[BaseException],
        kind: str,
        canary_in: str | None,
        descendant: bool,
        secondary: list[str],
    ) -> None:
        original = factory()
        out = drive(original, canary_in=canary_in, descendant=descendant, assembly_error=True)
        assert_preserved(out, original)
        (record,) = out.case_records()
        assert record["secondary_findings"] == secondary  # never hard-coded empty
        scan = scan_of(record)
        assert len(scan) == 8
        leaks = [entry for entry in scan if entry.endswith(":leak")]
        assert leaks == ([f"{canary_in}:leak"] if canary_in else [])
        # a record that says ``leak`` always says ``canary_leak``, and the reverse
        assert ("canary_leak" in secondary) == bool(leaks)
        if descendant:
            assert record["descendants"] == "descendant_leak"
            assert record["descendant_report"] == [{"pid": ROOT_PID + 1, "name": "leaky"}]
        else:
            assert record["descendants"] == "no_descendants_remaining"
            assert "descendant_report" not in record
        assert record["cleanup_failed"] == ["evidence"]
        assert CANARY not in json.dumps(out.records)

    @pytest.mark.parametrize(
        "name",
        ["Interrúpt", "Ж", "a-b", "X" * 65, "Bad\nName", "", "1Name", "with space"],
    )
    def test_an_unsafe_exception_class_becomes_unknown_exception(self, name: str) -> None:
        for assembly_error in (True, False):
            original = named(name, BaseException)
            out = drive(original, canary_in="logs", assembly_error=assembly_error)
            assert out.raised is original
            (record,) = out.case_records()
            assert record["exception_class"] == "unknown_exception"
            assert record["secondary_findings"] == ["canary_leak"]  # the finding is not dropped
            assert "logs:leak" in record["canary_scan"]  # type: ignore[operator]
            assert name.strip() == "" or name not in json.dumps(out.records)
            assert str(out.run_level()["primary_failure"]).endswith(":unknown_exception")

    def test_both_findings_and_a_failing_observation_are_all_kept(self) -> None:
        original = KeyboardInterrupt()
        out = drive(
            original,
            canary_in="console",
            descendant=True,
            observation_error=True,
            assembly_error=True,
        )
        assert_preserved(out, original)
        (record,) = out.case_records()
        assert record["cleanup_failed"] == ["descendants", "evidence"]  # in cleanup order
        assert record["secondary_findings"] == ["canary_leak"]  # no descendant was observed
        assert record["outcome"] == "interrupted"

    def test_the_fallback_is_built_from_the_findings_not_the_failed_record(self) -> None:
        """The clock that broke the normal record is never consulted again."""
        findings = lm.CaseFindings(S.L1)
        findings.record_streams(CANARY, {**clean_streams(), "events": f"x {CANARY}"})
        findings.descendants = O.DESCENDANT_LEAK
        findings.descendant_report = [{"pid": 7, "name": "leaky"}]
        findings.cleanup_failed.append("evidence")
        record = lm._fallback_record(findings, CANARY, case=S.L1, interrupt=KeyboardInterrupt())
        assert set(record) == {*FALLBACK_FIELDS, "descendants", "descendant_report"}
        assert record["secondary_findings"] == ["canary_leak", "descendant_leak"]
        assert record["canary_scan"][4] == "events:leak"  # type: ignore[index]
        assert lm.evidence(**record) == record  # validated, with its canary_scan
        assert len(record["canary_scan"]) == 8  # type: ignore[arg-type]

    def test_a_fallback_missing_canary_scan_is_rejected_not_swallowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = lm.evidence

        def without_scan(**fields: object) -> dict[str, object]:
            if "cleanup_failed" in fields:
                fields.pop("canary_scan", None)
            return real(**fields)

        monkeypatch.setattr(lm, "evidence", without_scan)
        with pytest.raises(lm.EvidenceError):
            lm._fallback_record(
                lm.CaseFindings(S.L1), CANARY, case=S.L1, interrupt=KeyboardInterrupt()
            )
        original = KeyboardInterrupt()
        out = drive(original, assembly_error=True)
        assert_preserved(out, original)
        only_marker(out)  # detected: nothing is emitted silently, the fixed marker is reported

    def test_a_failing_fallback_format_reports_only_the_fixed_marker(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = lm.evidence

        def refuse(**fields: object) -> dict[str, object]:
            if "cleanup_failed" in fields:
                raise lm.EvidenceError("PLANTED-format-4417")
            return real(**fields)

        monkeypatch.setattr(lm, "evidence", refuse)
        original = asyncio.CancelledError("PLANTED-original-4417")
        out = drive(original, cases=(S.L1, S.L3), assembly_error=True, canary_in="logs")
        assert_preserved(out, original)
        only_marker(out)
        assert out.called == [S.L1]  # still no later case

    def test_a_failing_fallback_emission_reports_only_the_fixed_marker(self) -> None:
        original = KeyboardInterrupt("PLANTED-original-4417")
        out = drive(
            original,
            assembly_error=True,
            emit_fails=lambda record: "cleanup_failed" in record,
            descendant=True,
            canary_in="events",
        )
        assert_preserved(out, original)
        only_marker(out)

    def test_when_even_the_marker_fails_nothing_is_printed_and_the_interrupt_propagates(
        self,
    ) -> None:
        printed: list[str] = []

        def broken_mark(line: str) -> None:
            printed.append(line)
            raise RuntimeError("PLANTED-marker-4417")

        original = KeyboardInterrupt()
        out = drive(
            original,
            assembly_error=True,
            emit_fails=lambda r: "cleanup_failed" in r,
            mark=broken_mark,
        )
        assert_preserved(out, original)
        assert printed == ["evidence_fallback_failed: L1"]  # fixed text only, then it failed
        assert out.case_records() == []

    def test_the_marker_is_fixed_text_for_every_case(self) -> None:
        for case in lm.Case:
            assert re.fullmatch(
                r"evidence_fallback_failed: L[0-3]", lm.fallback_failure_marker(case)
            )
        with pytest.raises(ValueError):
            lm.fallback_failure_marker("PLANTED-not-a-case")  # type: ignore[arg-type]

    def test_the_marker_channel_accepts_only_the_fixed_line(self) -> None:
        plugin = lm.ZeroSkipPlugin()
        config = make_config()
        config.pluginmanager.register(plugin, lm.ZERO_SKIP_PLUGIN_NAME)
        mark = lm._default_marker(config)
        mark("PLANTED-free-text-4417")
        mark("evidence_fallback_failed: L9")
        mark("evidence_fallback_failed: L1\nmore")
        mark("evidence_fallback_failed: L1")
        assert plugin.evidence_lines == ["evidence_fallback_failed: L1"]

    def test_an_ordinary_failure_never_uses_the_fallback(self) -> None:
        """Only a cancellation has a fallback: an ordinary assembly failure is not swallowed."""
        with pytest.raises(RuntimeError):
            drive(RuntimeError("boom"), assembly_error=True)

    @needs_bash
    def test_the_marker_reaches_the_saved_output_and_nothing_else_does(self, exact: Exact) -> None:
        exact.module(SURFACE_BODY + FALLBACK_TEST)
        ran = exact.run("test_surface.py::test_fallback_failure")
        assert ran.returncode == 2  # the interrupt, through ``pipefail`` and ``tee``
        assert "evidence_fallback_failed: L1" in ran.saved.splitlines()
        assert evidence_records(ran.saved) == []
        for part in ("original", "clock", "emit"):
            assert f"PLANTED-fallback-{part}-4417" not in ran.saved
        assert output_problems(ran.saved) == []
        assert local_path_problems(ran.saved, exact.sandbox.pytester.path) == []


FALLBACK_TEST = """


def test_fallback_failure(pytestconfig):
    async def runner(case):
        raise KeyboardInterrupt("PLANTED-fallback-original-4417")

    ticks = {"n": 0}

    def clock():
        ticks["n"] += 1
        if ticks["n"] >= 2:
            raise RuntimeError("PLANTED-fallback-clock-4417")
        return 0.0

    def emit(record):
        raise RuntimeError("PLANTED-fallback-emit-4417")

    asyncio.run(
        lm.run_ordered_cases(
            {lm.Case.L1: runner},
            quota=lm.QuotaCounter(),
            emit=emit,
            cases=(lm.Case.L1,),
            clock=clock,
            mark=lm._default_marker(pytestconfig),
        )
    )
"""


# ---------------------------------------------------------------------------
# H33: the cleanup_failed schema
# ---------------------------------------------------------------------------


class TestCleanupSchema:
    def test_the_enum_is_exactly_the_two_steps_that_can_fail(self) -> None:
        assert lm.CLEANUP_STEPS == ("descendants", "evidence")
        assert "scan" not in lm.CLEANUP_STEPS

    @pytest.mark.parametrize(
        "value", [["descendants"], ["evidence"], ["descendants", "evidence"]], ids=str
    )
    def test_the_validator_accepts_the_fixed_shapes(self, value: list[str]) -> None:
        assert lm.evidence(cleanup_failed=value)["cleanup_failed"] == value

    @pytest.mark.parametrize(
        "value",
        [
            [],  # absent, never empty
            ["scan"],  # the removed value
            ["descendants", "scan"],
            ["scan", "descendants", "evidence"],
            ["evidence", "descendants"],  # wrong order
            ["descendants", "descendants"],  # duplicate
            ["evidence", "evidence"],
            ["descendants", "evidence", "evidence"],  # longer than the enum
            ["secret detail"],  # free text
            ["Descendants"],
            ["descendants: detail"],
            "descendants",  # not a list
            ("descendants",),
            {"descendants": True},
            [1],
            [None],
            [["descendants"]],
        ],
        ids=repr,
    )
    def test_the_validator_rejects_everything_else(self, value: object) -> None:
        with pytest.raises(lm.EvidenceError) as info:
            lm.evidence(cleanup_failed=value)
        assert "secret detail" not in str(info.value)

    def test_ordered_cleanup_is_the_enum_in_order_each_once(self) -> None:
        assert lm.ordered_cleanup(["evidence", "descendants", "evidence"]) == [
            "descendants",
            "evidence",
        ]
        assert lm.ordered_cleanup(["scan", "free text"]) == []
        assert lm.ordered_cleanup([]) == []

    def test_every_enum_value_has_a_real_emitting_path(self) -> None:
        """The code appends exactly the enum's values; a value without a path cannot exist."""
        appended: set[str] = set()
        for node in ast.walk(ast.parse(LIVE_MODULE.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "cleanup_failed"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                appended.add(str(node.args[0].value))
        assert appended == set(lm.CLEANUP_STEPS)

    def test_descendants_is_emitted_when_the_observation_raises(self) -> None:
        out = drive(KeyboardInterrupt(), observation_error=True)
        assert out.case_records()[0]["cleanup_failed"] == ["descendants"]
        ordinary = drive(RuntimeError("x"), observation_error=True)
        (record,) = ordinary.case_records()
        assert record["cleanup_failed"] == ["descendants"]
        assert record["outcome"] == "case_failed"  # an ordinary outcome stays what it was

    def test_evidence_is_emitted_when_the_assembly_raises(self) -> None:
        out = drive(asyncio.CancelledError(), assembly_error=True)
        assert out.case_records()[0]["cleanup_failed"] == ["evidence"]

    def test_both_steps_are_reported_in_cleanup_order(self) -> None:
        out = drive(KeyboardInterrupt(), observation_error=True, assembly_error=True)
        assert out.case_records()[0]["cleanup_failed"] == ["descendants", "evidence"]

    @pytest.mark.parametrize(("canary_in", "descendant", "secondary"), FINDING_ROWS)
    def test_it_never_overrides_the_cancellation_or_hides_a_finding(
        self, canary_in: str | None, descendant: bool, secondary: list[str]
    ) -> None:
        original = KeyboardInterrupt()
        out = drive(original, canary_in=canary_in, descendant=descendant, assembly_error=True)
        assert_preserved(out, original)
        (record,) = out.case_records()
        assert record["outcome"] == "interrupted"
        assert record["secondary_findings"] == secondary
        assert record["cleanup_failed"] == ["evidence"]

    def test_it_is_absent_when_no_step_failed(self) -> None:
        for script in (O.OK, O.CASE_FAILED, KeyboardInterrupt(), RuntimeError("x")):
            out = drive(script)
            assert "cleanup_failed" not in out.case_records()[0]


# ---------------------------------------------------------------------------
# H34: stale-literal hygiene
# ---------------------------------------------------------------------------

# The design's own check, built from pieces so this file does not contain what it searches for.
STALE_GREP = "|".join(("X[2-5]", "Phase " + "[AB]", "adapters " + "are wired"))
STALE_WORD_RE = re.compile(r"\b(?:" + STALE_GREP + r")\b")
TEST_MODULES = (Path(__file__), LIVE_MODULE)


def stale_literals(source: str) -> list[str]:
    """Lines holding a planning label as a literal, like ``grep -nwE`` over the same lines."""
    return [
        f"{number}:{line}"
        for number, line in enumerate(source.splitlines(), start=1)
        if STALE_WORD_RE.search(line)
    ]


class TestStaleLiteralHygiene:
    def test_the_designs_grep_finds_nothing_in_the_two_modules(self) -> None:
        for path in TEST_MODULES:
            assert stale_literals(path.read_text()) == [], path.name

    @pytest.mark.skipif(shutil.which("grep") is None, reason="needs grep")
    def test_the_real_grep_finds_nothing_either(self) -> None:
        done = subprocess.run(
            ["grep", "-nwE", STALE_GREP, *map(str, TEST_MODULES)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 1 and done.stdout == ""  # 1 = no match, no error

    @pytest.mark.skipif(shutil.which("grep") is None, reason="needs grep")
    def test_the_runbook_has_no_label_either(self) -> None:
        done = subprocess.run(
            ["grep", "-nE", "X[0-9]|Phase " + "[AB]", str(RUNBOOK_PATH)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 1 and done.stdout == ""

    @pytest.mark.parametrize(
        "literal",
        [
            "X" + "2",
            "X" + "3",
            "X" + "4",
            "X" + "5",
            "Phase " + "A",
            "Phase " + "B",
            "adapters " + "are wired",
        ],
    )
    def test_the_scan_detects_each_stored_literal(self, literal: str) -> None:
        assert stale_literals(f'x = "{literal}"\n')
        assert stale_literals(f"# {literal} now\n")
        assert (
            stale_literals(f'x = "{literal[:-1]}" + "{literal[-1]}"\n') == []
        )  # built from pieces

    def test_the_drift_fixtures_build_their_labels_from_pieces(self) -> None:
        """The negative runbook and stale-comment fixtures never store the exact literal."""
        source = Path(__file__).read_text()
        for needle in ("## Phase " + "B: before either operation", '"X' + '2"', '"X' + '3"'):
            assert needle not in source
        # ... yet the fixtures still drive the detectors
        piece = "".join(("X", "2"))
        assert runbook_contract_problems(f"{piece} readiness-only check")
        assert stale_status("# " + "Phase " + "B\n")

    def test_a_directly_stored_label_in_a_test_module_is_caught(self, tmp_path: Path) -> None:
        bad = tmp_path / "test_bad.py"
        bad.write_text(f'FIXTURE = "## {"Phase " + "B"}: before"\n')
        assert stale_literals(bad.read_text())


def precedence_rows() -> list[Any]:
    """Every ordinary row T1-T7 of the design's precedence table."""
    timeout = TimeoutError("timed out")
    return [
        # id, cases, script, canary_in, descendant, incomplete, primary, secondary, adapter
        (
            "T1",
            (S.L1, S.L3),
            O.INCONCLUSIVE,
            None,
            False,
            False,
            O.INCONCLUSIVE,
            [],
            O.INCONCLUSIVE,
        ),
        ("T2", (S.L1, S.L3), O.OK, "console", False, False, O.CANARY_LEAK, [], O.OK),
        ("T3", (S.L1, S.L3), O.OK, None, True, False, O.DESCENDANT_LEAK, [], O.OK),
        (
            "T4",
            (S.L1, S.L3),
            O.INCONCLUSIVE,
            "console",
            True,
            False,
            O.CANARY_LEAK,
            [O.DESCENDANT_LEAK],
            O.INCONCLUSIVE,
        ),
        ("T5", (S.L1, S.L3), O.OK, "events", False, False, O.CANARY_LEAK, [], O.OK),
        (
            "T5-both",
            (S.L1, S.L3),
            O.OK,
            "events",
            True,
            False,
            O.CANARY_LEAK,
            [O.DESCENDANT_LEAK],
            O.OK,
        ),
        (
            "T6",
            (S.L3, S.L2),
            timeout,
            "exceptions",
            True,
            False,
            O.CANARY_LEAK,
            [O.DESCENDANT_LEAK],
            O.INCONCLUSIVE,
        ),
        (
            "T7-incomplete",
            (S.L1, S.L3),
            O.OK,
            None,
            False,
            True,
            O.CANARY_SCAN_INCOMPLETE,
            [],
            O.OK,
        ),
        ("T7-descendant", (S.L1, S.L3), O.OK, None, True, True, O.DESCENDANT_LEAK, [], O.OK),
        (
            "leak-beats-incomplete",
            (S.L1, S.L3),
            O.OK,
            "tmp_files",
            False,
            True,
            O.CANARY_LEAK,
            [],
            O.OK,
        ),
        (
            "scripted-canary-outcome",
            (S.L1, S.L3),
            lm.HarnessFailure(O.CANARY_LEAK),
            None,
            True,
            False,
            O.CANARY_LEAK,
            [O.DESCENDANT_LEAK],
            O.CANARY_LEAK,
        ),
    ]


class TestOutcomePrecedence:
    """H19: canary leak > descendant leak > incomplete scan > adapter outcome."""

    @pytest.mark.parametrize("row", precedence_rows(), ids=lambda r: r[0])
    def test_row(self, row: tuple[Any, ...]) -> None:
        _, cases, script, canary_in, descendant, incomplete, primary, secondary, adapter = row
        out = drive(
            script, cases=cases, canary_in=canary_in, descendant=descendant, incomplete=incomplete
        )
        assert out.result is not None and out.raised is None
        first = out.result.results[0]
        assert first.outcome is primary
        assert first.secondary == tuple(secondary)
        assert first.adapter_outcome is adapter
        (record, *_) = out.case_records()
        assert record["outcome"] == primary.value
        assert record["adapter_outcome"] == adapter.value
        assert record["secondary_findings"] == [o.value for o in secondary]
        assert record["interrupted"] == "none"
        # the abort behaviour follows the primary outcome: no later case runs
        assert out.called == [cases[0]]
        assert out.result.results[1].status == "not_executed"
        if primary in lm.SAFETY_OUTCOMES:
            assert {r.outcome for r in out.result.results[1:]} == {
                O.NOT_EXECUTED_AFTER_SAFETY_FAILURE
            }
        # the aggregate keeps the primary and lists every secondary finding
        text = lm.aggregate_text(out.result)
        assert f"first_failure: {cases[0].value}:{primary.value}:" in text
        for finding in secondary:
            assert f"{cases[0].value}:{finding.value}" in text.split("also:")[1]
        assert CANARY not in text and CANARY not in json.dumps(out.records)

    def test_a_passing_adapter_never_masks_a_leak(self) -> None:
        out = drive(O.OK, canary_in="workflow_result")
        assert out.result is not None
        assert out.result.results[0].outcome is O.CANARY_LEAK
        assert not out.result.succeeded
        with pytest.raises(pytest.fail.Exception):
            lm.finalize(out.result)

    def test_the_resolution_function_covers_every_combination(self) -> None:
        for canary in (False, True):
            for descendant in (False, True):
                for incomplete in (False, True):
                    got = lm.resolve_outcome(
                        O.INCONCLUSIVE,
                        canary_leak=canary,
                        descendant_leak=descendant,
                        scan_incomplete=incomplete,
                    )
                    assert got.adapter_outcome is O.INCONCLUSIVE
                    if canary:
                        assert got.primary is O.CANARY_LEAK
                        assert got.secondary == ((O.DESCENDANT_LEAK,) if descendant else ())
                    elif descendant:
                        assert (got.primary, got.secondary) == (O.DESCENDANT_LEAK, ())
                    elif incomplete:
                        assert (got.primary, got.secondary) == (O.CANARY_SCAN_INCOMPLETE, ())
                    else:
                        assert (got.primary, got.secondary) == (O.INCONCLUSIVE, ())


class TestCanaryScanEvidence:
    """H20: every case carries eight fixed strings, on every path, and never a value."""

    @pytest.mark.parametrize("stream", lm.REQUIRED_STREAMS)
    def test_a_canary_planted_in_each_stream_leaks_that_stream_only(self, stream: str) -> None:
        out = drive(O.OK, canary_in=stream)
        (record,) = out.case_records()
        assert record["canary_scan"] == [
            f"{name}:{'leak' if name == stream else 'clean'}" for name in lm.REQUIRED_STREAMS
        ]
        assert record["outcome"] == "canary_leak"
        assert CANARY not in json.dumps(out.records)

    @pytest.mark.parametrize(
        "script",
        [O.OK, O.INCONCLUSIVE, RuntimeError("x"), TimeoutError("t"), KeyboardInterrupt()],
        ids=["success", "ordinary-failure", "exception", "timeout", "cancellation-cleanup"],
    )
    def test_emitted_on_every_path(self, script: object) -> None:
        out = drive(script)
        (record,) = out.case_records()
        assert lm.scan_is_clean_and_complete(record["canary_scan"], "L1")
        assert isinstance(record["canary_scan"], list) and len(record["canary_scan"]) == 8
        assert [e.split(":")[0] for e in scan_of(record)] == list(lm.REQUIRED_STREAMS)

    def test_a_case_that_never_reached_its_adapter_is_reported_as_produced_nothing(self) -> None:
        """A refused case scanned nothing because nothing ran; the entry says so."""
        result, _, emitted = run_machine(pre_hooks={S.L2: _raise(O.L2_L3_NOT_PAIRED)})
        refused = next(r for r in emitted if r["case"] == "L2")
        assert refused["canary_scan"] == list(lm.EMPTY_SCAN)
        assert result.results[-1].outcome is O.L2_L3_NOT_PAIRED

    def test_no_matched_text_canary_value_or_path_is_retained(self, tmp_path: Path) -> None:
        out = drive(O.OK, canary_in="stdout_stderr", descendant=True)
        text = json.dumps(out.records)
        assert CANARY not in text and str(tmp_path) not in text and "leaked" not in text
        for record in out.records:
            for entry in cast("list[str]", record.get("canary_scan", [])):
                assert re.fullmatch(
                    r"(stdout_stderr|console|logs|exceptions|events|workflow_result|evidence"
                    r"|tmp_files):(clean|leak|not_available)",
                    entry,
                )

    def test_not_available_only_where_the_design_allows_it(self) -> None:
        base = clean_streams()
        for name in lm.REQUIRED_STREAMS:
            streams = {**base, name: lm.NOT_AVAILABLE}
            for case in ("L0", "L1", "L3", "L2"):
                report = lm.scan_report(CANARY, streams, case=case)
                allowed = name == "workflow_result" or (
                    case == "L0" and name in ("console", "events")
                )
                assert report.incomplete is (not allowed), (name, case)
                assert report.entries[lm.REQUIRED_STREAMS.index(name)] == f"{name}:not_available"
                assert lm.scan_is_clean_and_complete(list(report.entries), case) is allowed

    def test_a_missing_stream_is_incomplete_for_every_case_and_stream(self) -> None:
        for name in lm.REQUIRED_STREAMS:
            streams = clean_streams()
            del streams[name]
            assert lm.scan_report(CANARY, streams, case="L0").incomplete

    def test_a_scan_error_is_incomplete_not_clean(self) -> None:
        class Unscannable:
            def __repr__(self) -> str:
                raise RuntimeError("no repr")

            def __str__(self) -> str:
                raise RuntimeError("no str")

        streams = clean_streams()
        streams["events"] = Unscannable()
        report = lm.scan_report(CANARY, streams, case="L1")
        assert report.incomplete and "events:not_available" in report.entries

    def test_a_leak_seen_at_emit_time_survives_a_later_clean_scan(self) -> None:
        findings = lm.CaseFindings(S.L1)
        findings.record_streams(CANARY, clean_streams(), forced_leaks=("logs",))
        findings.record_streams(CANARY, clean_streams())  # the bounded buffer no longer holds it
        assert findings.entries[lm.REQUIRED_STREAMS.index("logs")] == "logs:leak"
        assert findings.canary_leak

    def test_official_is_false_when_the_scan_is_incomplete_or_leaks(self) -> None:
        assert lm.scan_is_clean_and_complete(list(lm.EMPTY_SCAN), "L1")
        assert not lm.scan_is_clean_and_complete(["x"], "L1")
        leaky = [
            f"{n}:leak" if n == "logs" else e
            for n, e in zip(lm.REQUIRED_STREAMS, lm.EMPTY_SCAN, strict=True)
        ]
        assert not lm.scan_is_clean_and_complete(leaky, "L1")
        incomplete = [
            f"{n}:not_available" if n == "events" else e
            for n, e in zip(lm.REQUIRED_STREAMS, lm.EMPTY_SCAN, strict=True)
        ]
        assert not lm.scan_is_clean_and_complete(incomplete, "L1")
        assert lm.scan_is_clean_and_complete(incomplete, "L0")


# ============================================================================
# H16: passive observer
# ============================================================================


class FakeInner:
    def __init__(
        self,
        items: Sequence[object],
        *,
        raise_after: BaseException | None = None,
        block: bool = False,
    ) -> None:
        self.items = list(items)
        self.raise_after = raise_after
        self.block = block
        self.index = 0
        self.aiter_calls = 0
        self.aclose_calls = 0

    def __aiter__(self) -> FakeInner:
        self.aiter_calls += 1
        return self

    async def __anext__(self) -> object:
        if self.index < len(self.items):
            self.index += 1
            return self.items[self.index - 1]
        if self.block:
            await asyncio.Event().wait()
        if self.raise_after is not None:
            raise self.raise_after
        raise StopAsyncIteration

    async def aclose(self) -> None:
        self.aclose_calls += 1


class FakeAssistant:
    def __init__(self, error: object = None) -> None:
        self.error = error
        self.content = "SECRET-TEXT-NEVER-RECORDED"


class FakeResult:
    def __init__(self, status: object = None, is_error: object = None) -> None:
        self.api_error_status = status
        self.is_error = is_error
        self.result = "SECRET-RESULT-NEVER-RECORDED"


def make_client_class(inner: FakeInner) -> type:
    class FakeClient:
        original_calls = 0

        def receive_response(self) -> FakeInner:
            type(self).original_calls += 1
            return inner

    return FakeClient


class TestObserver:
    async def test_normal_completion_is_transparent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        messages = [FakeAssistant("authentication_failed"), FakeResult(401, True)]
        inner = FakeInner(messages)
        client_cls = make_client_class(inner)
        sink: list[lm.Observation] = []
        with monkeypatch.context() as scoped:
            lm.install_spy(scoped, client_cls, sink)
            out = [m async for m in client_cls().receive_response()]
        assert client_cls.original_calls == 1  # type: ignore[attr-defined]
        assert inner.aiter_calls == 1  # iterated exactly once
        assert len(out) == 2 and all(a is b for a, b in zip(out, messages, strict=True))
        assert inner.aclose_calls == 1  # explicit, not left to garbage collection
        assert sink == [
            lm.Observation("FakeAssistant", "authentication_failed", None, None),
            lm.Observation("FakeResult", None, 401, True),
        ]

    async def test_early_outer_close_finalizes_inner(self, monkeypatch: pytest.MonkeyPatch) -> None:
        inner = FakeInner([FakeResult(), FakeResult()])
        client_cls = make_client_class(inner)
        with monkeypatch.context() as scoped:
            lm.install_spy(scoped, client_cls, [])
            gen = client_cls().receive_response()
            await gen.__anext__()
            await gen.aclose()
        assert inner.aclose_calls == 1
        assert inner.index == 1  # nothing pre-fetched

    async def test_unstarted_outer_needs_no_close(self, monkeypatch: pytest.MonkeyPatch) -> None:
        inner = FakeInner([FakeResult()])
        client_cls = make_client_class(inner)
        with monkeypatch.context() as scoped:
            lm.install_spy(scoped, client_cls, [])
            gen = client_cls().receive_response()
            await gen.aclose()
        assert client_cls.original_calls == 1  # type: ignore[attr-defined]
        assert inner.aiter_calls == 0 and inner.aclose_calls == 0

    async def test_exception_is_preserved_and_inner_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        boom = ValueError("same object")
        inner = FakeInner([FakeResult()], raise_after=boom)
        client_cls = make_client_class(inner)
        with monkeypatch.context() as scoped:
            lm.install_spy(scoped, client_cls, [])
            with pytest.raises(ValueError) as info:
                async for _ in client_cls().receive_response():
                    pass
        assert info.value is boom
        assert inner.aclose_calls == 1

    async def test_cancellation_is_preserved_and_inner_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        inner = FakeInner([FakeResult()], block=True)
        client_cls = make_client_class(inner)
        started = asyncio.Event()

        async def consume() -> None:
            async for _ in client_cls().receive_response():
                started.set()

        with monkeypatch.context() as scoped:
            lm.install_spy(scoped, client_cls, [])
            task = asyncio.create_task(consume())
            await started.wait()
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert inner.aclose_calls == 1

    async def test_patch_is_removed_after_each_case_and_reinstallable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        inner = FakeInner([])
        client_cls = make_client_class(inner)
        original = client_cls.__dict__["receive_response"]
        for _ in range(2):
            sink: list[lm.Observation] = []
            with monkeypatch.context() as scoped:
                lm.install_spy(scoped, client_cls, sink)
                assert client_cls.__dict__["receive_response"] is not original
            assert client_cls.__dict__["receive_response"] is original  # nothing survives

    def test_recorder_keeps_typed_fields_only(self) -> None:
        assert set(lm.Observation.__dataclass_fields__) == {
            "type_name",
            "assistant_error",
            "api_error_status",
            "is_error",
        }
        recorded = lm.record_observation(FakeAssistant("free text that is not a literal"))
        assert recorded.assistant_error == "other"
        assert "SECRET" not in repr(recorded)
        assert "SECRET" not in repr(lm.record_observation(FakeResult(401)))

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (401, 401),
            (100, 100),
            (599, 599),
            (99, None),
            (600, None),
            (True, None),
            ("401", None),
            (None, None),
            (401.0, None),
        ],
    )
    def test_recorder_status_rules(self, status: object, expected: int | None) -> None:
        assert lm.record_observation(FakeResult(status)).api_error_status == expected

    def test_recorder_rejects_non_bool_is_error_and_unknown_error(self) -> None:
        assert lm.record_observation(FakeResult(is_error="yes")).is_error is None
        assert lm.record_observation(FakeResult(is_error=False)).is_error is False
        assert lm.record_observation(object()).assistant_error is None

    def test_missing_typed_signals_are_inconclusive(self) -> None:
        error = ProviderError("x", is_retryable=False)
        recorded = [lm.record_observation(FakeAssistant()), lm.record_observation(FakeResult())]
        assert lm.classify_l3(recorded, [error], []) is lm.Outcome.INCONCLUSIVE
        assert lm.classify_l3([], [error], []) is lm.Outcome.INCONCLUSIVE

    def test_real_sdk_client_attribute_exists_and_is_restored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("claude_agent_sdk")
        from claude_agent_sdk import ClaudeSDKClient

        original = ClaudeSDKClient.__dict__["receive_response"]
        with monkeypatch.context() as scoped:
            lm.install_spy(scoped, ClaudeSDKClient, [])  # installs only; nothing is instantiated
            assert ClaudeSDKClient.__dict__["receive_response"] is not original
        assert ClaudeSDKClient.__dict__["receive_response"] is original


# ============================================================================
# Adapter seams with fakes
# ============================================================================


def l0_fields(**overrides: object) -> dict[str, object]:
    """A complete, successful L0 evidence set (presence booleans and fixed enums only)."""
    base: dict[str, object] = {
        "auth_method_present": True,
        "api_provider_present": True,
        "api_provider_is_first_party": True,
        "subscription_type_present": True,
        "api_key_source_present": False,
        "billing_mode": "subscription",
        "billing_reason": "first_party_login",
        "first_party_constant": "validated",
    }
    return {**base, **overrides}


SUBSCRIPTION_USAGE: dict[str, object] = {
    "total_input_tokens": 12,
    "total_output_tokens": 8,
    "total_cost_usd": 0.001,
    "billing": {"state": "subscription", "breakdown": {"subscription": 1}},
}


def run_ok(**overrides: Any) -> lm.RunObservation:
    """A complete, successful L1 / L2 observation; tests break exactly one part of it."""
    from conductor.billing import SUBSCRIPTION_LABEL

    base: dict[str, Any] = {
        "events": [
            {
                "type": "agent_completed",
                "data": {"billing_mode": "subscription", "model": "claude-haiku-4-5-20251001"},
            }
        ],
        "exception": None,
        "streams": clean_streams(),
        "total_cost_usd": 0.001,
        "effective_model": "claude-haiku-4-5-20251001",
        "fields": {},
        "output": {"answer": "A workflow is a sequence of steps."},
        "usage": dict(SUBSCRIPTION_USAGE),
        "console_text": f"Total: $0.0010 ({SUBSCRIPTION_LABEL})",
    }
    return lm.RunObservation(**{**base, **overrides})


def run_invalid_key(sink: list[lm.Observation]) -> lm.RunObservation:
    sink.append(obs(error="authentication_failed", status=401))
    return lm.RunObservation(
        events=[],
        exception=ProviderError("rejected", is_retryable=False),
        streams=clean_streams(),
    )


class FakeAdapterSet:
    """Fakes for every seam; every external entry is recorded in ``calls``."""

    def __init__(
        self,
        script: dict[lm.Case, Callable[[list[lm.Observation]], lm.RunObservation]] | None = None,
        *,
        ready: bool = True,
    ) -> None:
        self.calls: list[str] = []
        self.script = script or {}
        self.ready = ready
        self.table: dict[int, tuple[int, str]] = {}
        self.sink: list[lm.Observation] = []
        self.on_execute: Callable[[lm.Case], None] | None = None

    def as_set(self) -> lm.AdapterSet:
        outer = self

        class Readiness:
            async def probe(self) -> lm.ReadinessObservation:
                outer.calls.append("readiness")
                return lm.ReadinessObservation(outer.ready, l0_fields())

        class Workflow:
            async def execute(self, variant: lm.CaseVariant) -> lm.RunObservation:
                outer.calls.append(f"execute:{variant.case.value}")
                if outer.on_execute is not None:
                    outer.on_execute(variant.case)
                default = lm.EXPECTED_OUTCOME[variant.case]
                builder = outer.script.get(
                    variant.case,
                    run_invalid_key
                    if default is lm.Outcome.INVALID_KEY
                    else (lambda sink: run_ok()),
                )
                return builder(outer.sink)

        class Cli:
            def resolve(self) -> lm.CliEvidence:
                outer.calls.append("cli")
                return lm.CliEvidence("bundled", "2.1.150")

        class Descendants:
            def snapshot(self) -> dict[int, tuple[int, str]]:
                return outer.table

        class Observer:
            def observing(self) -> Any:
                import contextlib

                @contextlib.contextmanager
                def cm() -> Any:
                    outer.sink = []
                    yield outer.sink

                return cm()

        return lm.AdapterSet(Readiness(), Workflow(), Cli(), Descendants(), Observer())


def official(
    tmp_path: Path,
    fake: FakeAdapterSet,
    **kwargs: Any,
) -> lm.SessionResult:
    clock = Clock()
    options: dict[str, Any] = {
        "readiness_check": lambda: None,
        "prereq_check": lambda: "bundled",
        "grace_s": 0.0,
        "sleep": clock.sleep,
        "git_state": lambda: (GIT_SHA, False),
        "facts": lambda: dict(FACTS),
    }
    return asyncio.run(
        lm.run_official_session(make_config(), tmp_path, fake.as_set(), **{**options, **kwargs})
    )


@pytest.mark.usefixtures("gates_on")
class TestAdapterSeams:
    def test_full_success_through_fakes(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet()
        result = official(tmp_path, fake)
        assert result.succeeded
        assert fake.calls == ["cli", "readiness", "execute:L1", "execute:L3", "execute:L2"]
        assert [r["case"] for r in result.evidence if "case" in r and r["case"] != "session"] == [
            "L0",
            "L1",
            "L3",
            "L2",
        ]
        lm.finalize(result)
        assert result.quota_attempts == 3
        assert all(
            "descendants" in r for r in result.evidence if r.get("case") in {"L1", "L3", "L2"}
        )

    @pytest.fixture
    def tripwire_hits(self, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        """In-process external-entry tripwires; the test asserts the list stays empty."""
        import socket

        hits: list[str] = []

        def arm(owner: Any, attr: str, name: str) -> None:
            def tripwire(*args: object, **kwargs: object) -> None:
                hits.append(name)
                raise AssertionError(f"tripwire: {name}")

            monkeypatch.setattr(owner, attr, tripwire)

        arm(subprocess.Popen, "__init__", "Popen")
        arm(asyncio, "create_subprocess_exec", "create_subprocess_exec")
        arm(asyncio, "create_subprocess_shell", "create_subprocess_shell")
        arm(os, "posix_spawn", "posix_spawn")
        arm(socket.socket, "connect", "socket.connect")
        arm(socket, "create_connection", "create_connection")
        return hits

    @staticmethod
    def _drifted(kind: str) -> Callable[..., dict[lm.Case, lm.CaseVariant]]:
        real = lm.build_variants

        def build(
            yaml_text: str, canary: str, environ: Any, **kwargs: Any
        ) -> dict[lm.Case, lm.CaseVariant]:
            variants = real(yaml_text, canary, environ, **kwargs)
            l2 = variants[S.L2]
            if kind == "config":
                config = dict(l2.config)
                config["agents"] = [{"name": "drifted"}]  # more than auth_mode differs
                variants[S.L2] = dataclasses.replace(l2, config=config)
            else:
                env = dataclasses.replace(
                    l2.env, set_names=(*l2.env.set_names, "ANTHROPIC_BASE_URL")
                )
                variants[S.L2] = dataclasses.replace(l2, env=env)
            return variants

        return build

    def test_m23_config_drift_stops_before_l3_and_l2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tripwire_hits: list[str]
    ) -> None:
        monkeypatch.setattr(lm, "build_variants", self._drifted("config"))
        fake = FakeAdapterSet()
        result = official(tmp_path, fake)
        assert [r.outcome for r in result.results] == [
            O.OK,
            O.OK,
            O.L2_L3_NOT_PAIRED,
            O.NOT_EXECUTED_AFTER_SAFETY_FAILURE,
        ]
        assert fake.calls == ["cli", "readiness", "execute:L1"]  # L3 and L2 never invoked
        assert result.quota_attempts == 1  # only L1; nothing consumed for L3/L2
        l3 = next(r for r in result.evidence if r.get("case") == "L3")
        assert l3["outcome"] == "l2_l3_not_paired"
        assert l3["attempted_quota_execution"] is False
        assert lm.run_level_record(result)["not_executed"] == (
            "L2:not_executed_after_safety_failure"
        )
        assert result.primary_failure == "L3:l2_l3_not_paired:HarnessFailure"
        assert not result.succeeded
        assert tripwire_hits == []

    def test_m23_env_name_drift_stops_before_l2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tripwire_hits: list[str]
    ) -> None:
        monkeypatch.setattr(lm, "build_variants", self._drifted("env"))
        fake = FakeAdapterSet()
        result = official(tmp_path, fake)
        # L3 runs only to reach the L2 boundary (invalid_key); L2 is refused by the env hook.
        assert [r.outcome for r in result.results] == [
            O.OK,
            O.OK,
            O.INVALID_KEY,
            O.L2_L3_NOT_PAIRED,
        ]
        assert fake.calls == ["cli", "readiness", "execute:L1", "execute:L3"]
        assert result.quota_attempts == 2  # the L2 attempt was not consumed
        l2 = next(r for r in result.evidence if r.get("case") == "L2")
        assert l2["outcome"] == "l2_l3_not_paired"
        assert l2["attempted_quota_execution"] is False
        assert result.primary_failure == "L2:l2_l3_not_paired:HarnessFailure"
        assert not result.succeeded
        assert tripwire_hits == []

    def test_cli_evidence_is_recorded_once_after_preflight(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet()
        result = official(tmp_path, fake)
        session = [r for r in result.evidence if r.get("case") == "session"]
        assert session == [
            {
                "case": "session",
                **FACTS,
                "git_sha": GIT_SHA,
                "git_dirty": False,
                "source_tree_verdict": "verified",
                "cli_class": "bundled",
                "cli_version": "2.1.150",
                "isolation_verdict": "isolated",
            }
        ]

    def test_l0_not_ready_aborts_everything_after_it(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet(ready=False)
        result = official(tmp_path, fake)
        assert [r.outcome for r in result.results] == [O.NOT_LOGGED_IN] + [
            O.NOT_EXECUTED_AFTER_L0_FAILURE
        ] * 3
        assert fake.calls == ["cli", "readiness"]
        with pytest.raises(pytest.fail.Exception):
            lm.finalize(result)

    def test_l3_fallback_never_reaches_l2(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet({S.L3: lambda sink: run_ok()})
        result = official(tmp_path, fake)
        assert [r.outcome for r in result.results][-2:] == [
            O.FELL_BACK_TO_LOGIN,
            O.NOT_EXECUTED_L3_FELL_BACK_TO_LOGIN,
        ]
        assert "execute:L2" not in fake.calls

    def test_l3_without_typed_signal_is_inconclusive(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet(
            {
                S.L3: lambda sink: lm.RunObservation(
                    events=[],
                    exception=ProviderError("x", is_retryable=False),
                    streams=clean_streams(),
                )
            }
        )
        result = official(tmp_path, fake)
        assert result.results[2].outcome is O.INCONCLUSIVE
        assert "execute:L2" not in fake.calls

    def test_canary_leak_overrides_and_aborts(self, tmp_path: Path) -> None:
        leaked = clean_streams()
        leaked["console"] = "the key was sk-ant-api03-CANARY-not-this-one"
        fake = FakeAdapterSet({S.L1: lambda sink: run_ok(streams=leaked)})
        canary = lm.make_canary("f" * 32)
        leaked["console"] = f"printed {canary}"
        result = official(tmp_path, fake, canary=canary)
        assert result.results[1].outcome is O.CANARY_LEAK
        assert [r.outcome for r in result.results[2:]] == [O.NOT_EXECUTED_AFTER_SAFETY_FAILURE] * 2
        assert fake.calls == ["cli", "readiness", "execute:L1"]
        assert canary not in str(result.evidence)

    def test_incomplete_streams_abort_even_when_the_run_succeeded(self, tmp_path: Path) -> None:
        partial = {"events": ""}
        fake = FakeAdapterSet({S.L1: lambda sink: run_ok(streams=partial)})
        result = official(tmp_path, fake)
        assert result.results[1].outcome is O.CANARY_SCAN_INCOMPLETE

    def test_l1_exception_is_inconclusive_and_class_is_recorded(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet(
            {S.L1: lambda sink: run_ok(events=[], exception=TimeoutError("secret-detail"))}
        )
        result = official(tmp_path, fake)
        assert result.results[1].outcome is O.INCONCLUSIVE
        record = next(r for r in result.evidence if r.get("case") == "L1")
        assert record["exception_class"] == "TimeoutError"
        assert "secret-detail" not in str(result.evidence)
        assert result.results[2].outcome is O.NOT_EXECUTED_AFTER_L1_FAILURE

    def test_unpriced_or_unreported_model_fails_l1(self, tmp_path: Path) -> None:
        result = official(
            tmp_path, FakeAdapterSet({S.L1: lambda sink: run_ok(total_cost_usd=None)})
        )
        assert result.results[1].outcome is O.UNPRICED_MODEL_LABEL_UNEXERCISED
        result = official(tmp_path, FakeAdapterSet({S.L1: lambda sink: run_ok(effective_model="")}))
        assert result.results[1].outcome is O.EFFECTIVE_MODEL_MISSING

    def test_descendant_leak_aborts_and_reports_pid_and_name(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet()

        def leak(case: lm.Case) -> None:
            if case is S.L1:
                fake.table = {os.getpid() + 100000: (os.getpid(), "leaky")}

        fake.on_execute = leak
        result = official(tmp_path, fake)
        assert result.results[1].outcome is O.DESCENDANT_LEAK
        assert result.results[-1].outcome is O.NOT_EXECUTED_AFTER_SAFETY_FAILURE
        record = next(r for r in result.evidence if r.get("case") == "L1")
        assert record["descendant_report"] == [{"pid": os.getpid() + 100000, "name": "leaky"}]

    def test_a_missing_adapter_set_fails_closed_after_preflight(self, tmp_path: Path) -> None:
        result = asyncio.run(
            lm.run_official_session(
                make_config(),
                tmp_path,
                None,
                readiness_check=lambda: None,
                prereq_check=lambda: "bundled",
            )
        )
        assert result.results[0].outcome is O.ADAPTERS_NOT_WIRED
        assert result.results[1].outcome is O.NOT_EXECUTED_AFTER_SAFETY_FAILURE

    def test_probe_readiness_runs_l0_only(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet()
        result = asyncio.run(
            lm.probe_readiness(
                make_config(),
                tmp_path,
                fake.as_set(),
                readiness_check=lambda: None,
                prereq_check=lambda: "bundled",
            )
        )
        assert result.succeeded and [r.case for r in result.results] == [S.L0]
        assert fake.calls == ["readiness"]

    @pytest.mark.parametrize("entry", ["probe_readiness", "run_official_session"])
    def test_the_fallback_marker_is_wired_through_both_session_entry_points(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
    ) -> None:
        """A cancelled case whose record cannot be built or emitted reports only the fixed line."""
        config = make_config()
        plugin = lm.ZeroSkipPlugin()
        config.pluginmanager.register(plugin, lm.ZERO_SKIP_PLUGIN_NAME)
        fake = FakeAdapterSet()
        original = KeyboardInterrupt("PLANTED-wiring-4417")

        def interrupted(case: lm.Case) -> None:
            raise original

        fake.on_execute = interrupted
        adapters = fake.as_set()
        if entry == "probe_readiness":

            async def cancelled_probe() -> lm.ReadinessObservation:
                raise original

            adapters.readiness.probe = cancelled_probe  # type: ignore[method-assign]

        real_record, real_emit = lm._case_record, lm.emit_evidence

        def no_record(*args: Any, interrupt: BaseException | None = None, **kwargs: Any) -> Any:
            if interrupt is None:
                return real_record(*args, interrupt=interrupt, **kwargs)
            raise RuntimeError("PLANTED-record-4417")

        def no_emit(record: Mapping[str, object]) -> str:
            if "cleanup_failed" in record:  # only the fallback record
                raise RuntimeError("PLANTED-emit-4417")
            return real_emit(record)

        monkeypatch.setattr(lm, "_case_record", no_record)
        monkeypatch.setattr(lm, "emit_evidence", no_emit)
        common: dict[str, Any] = {
            "readiness_check": lambda: None,
            "prereq_check": lambda: "bundled",
        }
        if entry == "run_official_session":
            common.update(git_state=lambda: (GIT_SHA, False), facts=lambda: dict(FACTS))
        with pytest.raises(KeyboardInterrupt) as info:
            asyncio.run(getattr(lm, entry)(config, tmp_path, adapters, **common))
        assert info.value is original
        interrupted_case = "L0" if entry == "probe_readiness" else "L1"
        marker = f"evidence_fallback_failed: {interrupted_case}"
        assert [ln for ln in plugin.evidence_lines if not ln.startswith("EVIDENCE ")] == [marker]
        assert "PLANTED" not in " ".join(plugin.evidence_lines)

    def test_both_entry_points_pass_the_marker_channel_on(self) -> None:
        """AST: each session entry point hands ``mark`` to ``run_session``."""
        tree = ast.parse(LIVE_MODULE.read_text())
        for name in ("probe_readiness", "run_official_session"):
            function = next(
                n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == name
            )
            calls = [
                n
                for n in ast.walk(function)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "run_session"
            ]
            assert len(calls) == 1
            assert "mark" in {kw.arg for kw in calls[0].keywords}, name

    def test_unsafe_preflight_enters_no_adapter(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet()
        for kwargs in (
            {"readiness_check": _raise(O.READINESS_STUB_ACTIVE)},
            {"prereq_check": _raise(O.PREREQ_CLI_MISSING)},
        ):
            result = official(tmp_path, fake, **kwargs)
            assert result.session_failure is not None
            assert fake.calls == []

    def test_terminalreporter_absence_is_a_preflight_failure(self, tmp_path: Path) -> None:
        fake = FakeAdapterSet()
        result = asyncio.run(
            lm.run_official_session(
                make_config(reporter=None),
                tmp_path,
                fake.as_set(),
                readiness_check=lambda: None,
                prereq_check=lambda: "bundled",
            )
        )
        assert result.session_failure == (O.PREREQ_TERMINALREPORTER_MISSING, "HarnessFailure")
        assert fake.calls == []

    def test_source_tree_mismatch_is_a_preflight_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import conductor

        monkeypatch.setattr(
            conductor, "__file__", str(tmp_path / "elsewhere" / "conductor" / "__init__.py")
        )
        fake = FakeAdapterSet()
        result = official(tmp_path, fake)
        assert result.session_failure == (O.SOURCE_TREE_MISMATCH, "HarnessFailure")
        assert fake.calls == []

    def test_invalid_model_override_is_a_preflight_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(lm.MODEL_ENV, "claude-haiku;rm")
        fake = FakeAdapterSet()
        result = official(tmp_path, fake, prereq_check=lambda: "bundled")
        assert result.session_failure == (O.INVALID_MODEL_OVERRIDE, "HarnessFailure")
        assert fake.calls == []


def _raise(outcome: lm.Outcome) -> Callable[[], Any]:
    def go() -> Any:
        raise lm.HarnessFailure(outcome)

    return go


# ============================================================================
# The real adapters, driven through the real provider / registry / engine
# with every CLI, SDK-transport, process and network boundary replaced
# ============================================================================
#
# Only two boundaries are replaced, and both are *below* production code:
#   * ``_run_auth_status_subprocess`` (the ``claude auth status --json`` spawn) -> ``AuthProbe``
#   * the SDK's process transport -> ``FakeTransport`` handed to the *real* ``ClaudeSDKClient``
# Everything above them is the shipped code: ``create_provider``, ``ProviderRegistry``,
# ``WorkflowEngine``, ``ClaudeAgentSdkProvider`` (readiness, billing derivation, execution),
# ``display_usage_summary`` and the real passive observer on ``ClaudeSDKClient.receive_response``.
# Tripwires are armed before any adapter is constructed, and every test asserts zero hits.

sdk = importlib.import_module("conductor.providers.claude_agent_sdk")

LOGIN_PAYLOAD: dict[str, object] = {
    "loggedIn": True,
    "authMethod": "claude.ai",
    "apiProvider": "firstParty",
    "subscriptionType": "max",
}
ANSWER_TEXT = json.dumps({"answer": "A workflow is a sequence of steps."})


@pytest.fixture
def boundary_hits(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fail-closed tripwires on every process / network / SDK-process entry (zero hits expected)."""
    import socket

    hits: list[str] = []

    def arm(owner: Any, attr: str, name: str) -> None:
        def tripwire(*args: object, **kwargs: object) -> None:
            hits.append(name)
            raise AssertionError(f"tripwire: {name}")

        monkeypatch.setattr(owner, attr, tripwire)

    arm(subprocess.Popen, "__init__", "Popen")
    arm(asyncio, "create_subprocess_exec", "create_subprocess_exec")
    arm(asyncio, "create_subprocess_shell", "create_subprocess_shell")
    arm(os, "posix_spawn", "posix_spawn")
    arm(socket.socket, "connect", "socket.connect")
    arm(socket, "create_connection", "create_connection")
    try:  # the SDK-side entries exist only where the optional extra is installed
        import anyio
        from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport
    except ImportError:
        return hits
    arm(anyio, "open_process", "anyio.open_process")
    arm(SubprocessCLITransport, "connect", "SubprocessCLITransport.connect")
    return hits


class AuthProbe:
    """Stands in for ``_run_auth_status_subprocess``: canned payloads, environment recorded."""

    def __init__(self, payload: dict[str, object] | None = None, *, returncode: int = 0) -> None:
        self.payload: dict[str, object] | None = dict(LOGIN_PAYLOAD) if payload is None else payload
        self.returncode = returncode
        self.envs: list[dict[str, str]] = []
        self.sites: list[str] = []  # who asked: direct (L0), validation or execution

    async def __call__(
        self, cli_path: object, child_env: Any, cwd: str, setting_sources: object
    ) -> tuple[bytes, bytes, int]:
        self.envs.append(dict(child_env))
        names: set[str] = set()
        frame = sys._getframe(1)
        while frame is not None:
            names.add(frame.f_code.co_name)
            frame = frame.f_back
        # ``execute`` starts its own probe in a separate task, so it has no ``execute`` frame.
        self.sites.append(
            "validation"
            if "validate_connection" in names
            else "direct"
            if "probe" in names
            else "execution"
        )
        return json.dumps(self.payload).encode(), b"", self.returncode


def sdk_frames(
    *,
    model: str = "claude-haiku-4-5-20251001",
    text: str = ANSWER_TEXT,
    error: str | None = None,
    is_error: bool = False,
    status: int | None = None,
    tokens: tuple[int, int] = (1200, 400),
) -> list[dict[str, Any]]:
    assistant: dict[str, Any] = {
        "type": "assistant",
        "session_id": "s-1",
        "message": {"model": model, "content": [{"type": "text", "text": text}]},
    }
    if error is not None:
        assistant["error"] = error
    result: dict[str, Any] = {
        "type": "result",
        "subtype": "error_during_execution" if is_error else "success",
        "duration_ms": 1,
        "duration_api_ms": 1,
        "is_error": is_error,
        "num_turns": 1,
        "session_id": "s-1",
        "result": text,
        "usage": {"input_tokens": tokens[0], "output_tokens": tokens[1]},
    }
    if status is not None:
        result["api_error_status"] = status
    return [assistant, result]


class Session:
    """One scripted SDK session: the transport the real ``ClaudeSDKClient`` will use."""

    def __init__(self, transport: Any, env_seen: dict[str, str | None]) -> None:
        self.transport = transport
        self.env_seen = env_seen


class Stack:
    """The hermetic boundary set for one test."""

    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capfd: pytest.CaptureFixture[str] | None,
        hits: list[str],
    ) -> None:
        self.tmp_path = tmp_path
        self.monkeypatch = monkeypatch
        self.capfd = capfd
        self.hits = hits
        self.config = make_config()
        self.probe = AuthProbe()
        self.sessions: list[Session] = []
        self.pending: list[Any] = []
        self.consumed = 0
        self.records: list[dict[str, object]] = []
        self.board = lm.FindingsBoard(CANARY)
        import claude_agent_sdk

        from tests.test_providers.claude_sdk_harness import FakeTransport

        self.transport_type = FakeTransport
        self.real_client = claude_agent_sdk.ClaudeSDKClient
        self.receive_original = claude_agent_sdk.ClaudeSDKClient.receive_response
        monkeypatch.setattr(sdk, "_run_auth_status_subprocess", self.probe)
        self.cli_path = tmp_path / "fake-claude"
        monkeypatch.setattr(sdk, "_find_claude_cli", lambda: self.cli_path)
        monkeypatch.setattr(sdk, "ClaudeSDKClient", self._make_client)

    def _make_client(self, options: Any = None, **_: Any) -> Any:
        if self.consumed >= len(self.pending):
            raise AssertionError("unscripted SDK session")
        transport = self.pending[self.consumed]
        self.consumed += 1
        return self.real_client(options, transport=transport)

    def script(
        self,
        frames: list[dict[str, Any]] | None,
        *,
        on_connect: Callable[[], None] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Queue one session; ``frames=None`` never answers (a hang).

        ``on_connect`` runs inside the fake transport's ``connect`` (test-only side effects:
        recording the process environment, logging, raising).
        """
        base = self.transport_type

        class Scripted(base):
            async def connect(self) -> None:
                if on_connect is not None:
                    on_connect()
                await super().connect()

        transport = Scripted(**kwargs)
        if frames is not None:
            transport.reply_with(*frames)
        self.pending.append(transport)
        return transport

    def adapters(self, canary: str = CANARY, **workflow: Any) -> lm.AdapterSet:
        adapters = lm.configured_adapters(
            self.config, self.tmp_path, self.monkeypatch, self.capfd, canary=canary
        )
        if workflow:
            adapters = dataclasses.replace(
                adapters,
                workflow=lm.RealWorkflowAdapter(
                    self.config,
                    self.tmp_path,
                    self.monkeypatch,
                    capfd=self.capfd,
                    canary=canary,
                    board=adapters.board,
                    **workflow,
                ),
            )
        bundled = Path(importlib.import_module("claude_agent_sdk").__file__ or "").parent
        cli = lm.RealCliEvidenceAdapter(
            self.config,
            self.tmp_path,
            find_cli=lambda: bundled / "_bundled" / "claude",
            run=lambda argv: "2.1.150 (Claude Code)",
        )
        return dataclasses.replace(adapters, cli=cli)

    def variants(self, canary: str = CANARY) -> dict[lm.Case, lm.CaseVariant]:
        return lm.build_variants(
            lm.EXAMPLE_PATH.read_text(), canary, os.environ, model=lm.DEFAULT_MODEL
        )

    def run_cases(
        self,
        cases: Sequence[lm.Case],
        *,
        read_table: Callable[[], dict[int, tuple[int, str]]] = dict,
        **workflow: Any,
    ) -> lm.SessionResult:
        """Run the real runners of ``cases`` through the real descendant check and case wrapper.

        Every emitted record is kept on ``self.records``, also when an interrupt propagates.
        """
        adapters = self.adapters(**workflow)
        runners = lm.build_case_runners(
            adapters,
            variants=self.variants(),
            canary=CANARY,
            requested_model=lm.DEFAULT_MODEL,
        )
        clock = Clock()
        protected = lm._protected_runners(
            self.config,
            self.tmp_path,
            adapters,
            {case: runners[case] for case in cases},
            read_table=read_table,
            sleep=clock.sleep,
            grace_s=0.0,
            board=adapters.board,
        )
        self.records = []
        self.board = adapters.board
        return asyncio.run(
            lm.run_ordered_cases(
                protected,
                quota=lm.QuotaCounter(),
                emit=self.records.append,
                cases=tuple(cases),
                board=adapters.board,
            )
        )

    def run_case(self, case: lm.Case, **workflow: Any) -> tuple[Any, list[dict[str, object]]]:
        """Run one case's real runner; returns ``(result, evidence)``."""
        result = self.run_cases((case,), **workflow)
        return result, self.records

    def session(self) -> lm.SessionResult:
        adapters = self.adapters()
        clock = Clock()
        return asyncio.run(
            lm.run_official_session(
                self.config,
                self.tmp_path,
                adapters,
                readiness_check=lambda: None,
                prereq_check=lambda: "bundled",
                canary=CANARY,
                read_table=dict,
                grace_s=0.0,
                sleep=clock.sleep,
                git_state=lambda: (GIT_SHA, False),
                facts=lambda: dict(FACTS),
            )
        )


@pytest.fixture
def stack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    boundary_hits: list[str],
    gates_on: None,
) -> Stack:
    pytest.importorskip("claude_agent_sdk")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return Stack(tmp_path, monkeypatch, capfd, boundary_hits)


def record_for(records: Sequence[dict[str, object]], case: str) -> dict[str, object]:
    return next(r for r in records if r.get("case") == case)


def scan_of(record: dict[str, object]) -> list[str]:
    """The ``canary_scan`` entries of an emitted record (the evidence contract makes it a list)."""
    return cast("list[str]", record["canary_scan"])


@pytest.mark.claude_auth_readiness_mocked
class TestRealAdaptersHappyPath:
    def test_full_official_session_through_real_production_paths(self, stack: Stack) -> None:
        stack.script(sdk_frames())  # L1
        stack.script(sdk_frames(error="authentication_failed", is_error=True, status=401))  # L3
        stack.script(sdk_frames())  # L2
        result = stack.session()
        assert [r.outcome for r in result.results] == [O.OK, O.OK, O.INVALID_KEY, O.OK]
        assert result.succeeded, result.primary_failure
        assert stack.hits == []
        assert stack.consumed == 3


def private_logger_state() -> dict[str, tuple[int, list[logging.Handler], bool, bool]]:
    """Level, handlers, propagation and disabled flag of the root logger and the private set."""
    out: dict[str, tuple[int, list[logging.Handler], bool, bool]] = {}
    for name in ("", *lm.PRIVATE_LOGGERS):
        logger = logging.getLogger(name)
        out[name or "<root>"] = (
            logger.level,
            list(logger.handlers),
            logger.propagate,
            logger.disabled,
        )
    return out


def env_recorder(seen: dict[str, str | None]) -> Callable[[], None]:
    """Record, at transport connect, what the child would inherit for the API-key variable."""

    def record() -> None:
        seen["key"] = os.environ.get("ANTHROPIC_API_KEY")

    return record


SDK_LOGGER = "claude_agent_sdk._internal.transport.subprocess_cli"


def canary_logger() -> None:
    """A DEBUG record naming the canary, from a logger the SDK really uses."""
    logging.getLogger(SDK_LOGGER).debug("leaked key %s", CANARY)


def raising(exc: BaseException) -> Callable[[], None]:
    def go() -> None:
        raise exc

    return go


def probe_l0(stack: Stack, payload: dict[str, object] | None = None) -> Any:
    if payload is not None:
        stack.probe.payload = payload
    records: list[dict[str, object]] = []
    result = asyncio.run(
        lm.probe_readiness(
            stack.config,
            stack.tmp_path,
            stack.adapters(),
            readiness_check=lambda: None,
            prereq_check=lambda: "bundled",
            emit=records.append,
            read_table=dict,
            grace_s=0.0,
            sleep=Clock().sleep,
            canary=CANARY,
        )
    )
    return result, records


def without(payload: dict[str, object], *names: str) -> dict[str, object]:
    return {k: v for k, v in payload.items() if k not in names}


@pytest.mark.claude_auth_readiness_mocked
class TestRealL0Adapter:
    """The real readiness adapter, provider construction and billing derivation (L0)."""

    def test_successful_subscription_derivation(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "route-token-value")
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://route.invalid")
        result, records = probe_l0(stack)
        assert result.succeeded
        l0 = record_for(records, "L0")
        assert l0["ready"] is True
        assert l0["billing_mode"] == "subscription"
        assert l0["billing_reason"] == "first_party_login"
        assert l0["subscription_type_present"] is True
        assert l0["api_key_source_present"] is False
        assert l0["api_provider_present"] is True
        assert l0["first_party_constant"] == "validated"
        assert l0["env_names_removed"] == ["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"]
        # The real readiness ran once, against the scrubbed environment ...
        assert len(stack.probe.envs) == 1
        assert not stack.probe.envs[0].get("ANTHROPIC_AUTH_TOKEN")
        assert not stack.probe.envs[0].get("ANTHROPIC_BASE_URL")
        # ... and the per-case context restored the caller's environment.
        assert os.environ["ANTHROPIC_AUTH_TOKEN"] == "route-token-value"
        assert stack.hits == []

    def test_not_ready(self, stack: Stack) -> None:
        result, records = probe_l0(stack, {"loggedIn": False})
        assert result.results[0].outcome is O.NOT_LOGGED_IN
        assert record_for(records, "L0")["ready"] is False
        with pytest.raises(pytest.fail.Exception):
            lm.finalize(result)
        assert stack.hits == []

    def test_missing_subscription_type_is_not_subscription_billing(self, stack: Stack) -> None:
        result, records = probe_l0(stack, without(LOGIN_PAYLOAD, "subscriptionType"))
        assert result.results[0].outcome is O.BILLING_NOT_SUBSCRIPTION
        l0 = record_for(records, "L0")
        assert l0["subscription_type_present"] is False
        assert l0["billing_mode"] == "unknown"
        assert l0["billing_reason"] == "no_subscription_evidence"
        assert not result.succeeded

    def test_api_key_source_reported_is_not_subscription_billing(self, stack: Stack) -> None:
        payload = {**LOGIN_PAYLOAD, "apiKeySource": "ANTHROPIC_API_KEY"}
        result, records = probe_l0(stack, payload)
        assert result.results[0].outcome is O.BILLING_NOT_SUBSCRIPTION
        assert record_for(records, "L0")["api_key_source_present"] is True

    def test_first_party_constant_absent_is_unexercised_and_passes(self, stack: Stack) -> None:
        result, records = probe_l0(stack, without(LOGIN_PAYLOAD, "apiProvider"))
        assert result.succeeded
        l0 = record_for(records, "L0")
        assert l0["first_party_constant"] == "unexercised"
        assert l0["api_provider_present"] is False

    def test_first_party_constant_mismatch_fails_instead_of_passing(self, stack: Stack) -> None:
        result, records = probe_l0(stack, {**LOGIN_PAYLOAD, "apiProvider": "bedrock"})
        assert result.results[0].outcome is O.FIRST_PARTY_MISMATCH
        l0 = record_for(records, "L0")
        assert l0["first_party_constant"] == "mismatch"
        assert l0["api_provider_is_first_party"] is False
        assert not result.succeeded

    def test_no_raw_auth_value_reaches_any_retained_stream(self, stack: Stack) -> None:
        raw = ("RAW-AUTH-METHOD-VALUE", "RAW-PLAN-VALUE", "RAW-KEY-SOURCE-VALUE")
        payload = {
            "loggedIn": True,
            "authMethod": raw[0],
            "apiProvider": "firstParty",
            "subscriptionType": raw[1],
            "apiKeySource": raw[2],
        }
        result, records = probe_l0(stack, payload)
        assert result.results[0].outcome is O.BILLING_NOT_SUBSCRIPTION
        assert stack.capfd is not None
        text = json.dumps(records) + "".join(stack.capfd.readouterr())
        assert not any(value in text for value in raw)

    def test_readiness_exception_is_a_failed_case_with_its_class(self, stack: Stack) -> None:
        class Boom(Exception):
            pass

        async def explode(*args: object, **kwargs: object) -> tuple[bytes, bytes, int]:
            raise Boom("unsafe text UNIQUE-READINESS-TEXT")

        stack.monkeypatch.setattr(sdk, "_run_auth_status_subprocess", explode)
        result, records = probe_l0(stack)
        assert result.results[0].outcome is O.CASE_FAILED
        assert result.results[0].exc_class == "Boom"
        record = record_for(records, "L0")
        assert record["exception_class"] == "Boom"
        assert lm.scan_is_clean_and_complete(record["canary_scan"], "L0")
        assert "UNIQUE-READINESS-TEXT" not in json.dumps(records)  # exception text never retained

    def test_readiness_exception_naming_the_canary_is_a_canary_leak_not_a_plain_failure(
        self, stack: Stack
    ) -> None:
        class Boom(Exception):
            pass

        async def explode(*args: object, **kwargs: object) -> tuple[bytes, bytes, int]:
            raise Boom("unsafe text " + CANARY)

        stack.monkeypatch.setattr(sdk, "_run_auth_status_subprocess", explode)
        result, records = probe_l0(stack)
        assert result.results[0].outcome is O.CANARY_LEAK
        assert result.results[0].adapter_outcome is O.CASE_FAILED
        record = record_for(records, "L0")
        assert record["exception_class"] == "Boom"
        assert "exceptions:leak" in scan_of(record)
        assert CANARY not in json.dumps(records)

    def test_l0_console_and_events_are_not_available_and_that_is_complete(
        self, stack: Stack
    ) -> None:
        result, records = probe_l0(stack)
        assert result.succeeded
        scan = record_for(records, "L0")["canary_scan"]
        assert scan == [
            "stdout_stderr:clean",
            "console:not_available",
            "logs:clean",
            "exceptions:clean",
            "events:not_available",
            "workflow_result:not_available",
            "evidence:clean",
            "tmp_files:clean",
        ]
        assert lm.scan_is_clean_and_complete(scan, "L0")
        assert not lm.scan_is_clean_and_complete(scan, "L1")  # not allowed for an inference case

    def test_a_canary_in_l0_stdout_is_found(self, stack: Stack) -> None:
        async def loud(*args: object, **kwargs: object) -> tuple[bytes, bytes, int]:
            os.write(1, f"status {CANARY}\n".encode())
            return json.dumps(LOGIN_PAYLOAD).encode(), b"", 0

        stack.monkeypatch.setattr(sdk, "_run_auth_status_subprocess", loud)
        result, records = probe_l0(stack)
        assert result.results[0].outcome is O.CANARY_LEAK
        assert "stdout_stderr:leak" in scan_of(record_for(records, "L0"))


class TestL0Predicates:
    """``assert_l0_success`` is a pure predicate: every branch is one fixed outcome."""

    def test_success_returns_the_evidence(self) -> None:
        fields = lm.assert_l0_success(True, l0_fields())
        assert fields["billing_mode"] == "subscription" and fields["ready"] is True
        assert lm.assert_l0_success(True, l0_fields(first_party_constant="unexercised"))

    @pytest.mark.parametrize(
        ("ready", "overrides", "drop", "expected"),
        [
            (False, {}, (), O.NOT_LOGGED_IN),
            (True, {}, ("api_key_source_present",), O.READINESS_EVIDENCE_MISSING),
            (True, {}, ("subscription_type_present",), O.READINESS_EVIDENCE_MISSING),
            (True, {"auth_method_present": "yes"}, (), O.READINESS_EVIDENCE_MISSING),
            (True, {}, ("first_party_constant",), O.READINESS_EVIDENCE_MISSING),
            (True, {"first_party_constant": "maybe"}, (), O.READINESS_EVIDENCE_MISSING),
            (True, {}, ("billing_mode",), O.READINESS_EVIDENCE_MISSING),
            (True, {"first_party_constant": "mismatch"}, (), O.FIRST_PARTY_MISMATCH),
            (True, {"billing_mode": "unknown"}, (), O.BILLING_NOT_SUBSCRIPTION),
            (True, {"billing_mode": "metered_api"}, (), O.BILLING_NOT_SUBSCRIPTION),
            (True, {"billing_reason": "api_key"}, (), O.BILLING_NOT_SUBSCRIPTION),
            (True, {"subscription_type_present": False}, (), O.READINESS_EVIDENCE_CONTRADICTION),
            (True, {"api_key_source_present": True}, (), O.READINESS_EVIDENCE_CONTRADICTION),
        ],
    )
    def test_each_failure_is_one_fixed_outcome(
        self,
        ready: bool,
        overrides: dict[str, object],
        drop: tuple[str, ...],
        expected: lm.Outcome,
    ) -> None:
        fields = {k: v for k, v in l0_fields(**overrides).items() if k not in drop}
        with raises_outcome(expected):
            lm.assert_l0_success(ready, fields)

    def test_first_party_constant_helper(self) -> None:
        assert lm.first_party_constant(None, "firstParty") == "unexercised"
        assert lm.first_party_constant("firstParty", "firstParty") == "validated"
        assert lm.first_party_constant("bedrock", "firstParty") == "mismatch"

    def test_readiness_fields_never_carry_a_raw_value(self) -> None:
        status = SimpleNamespace(
            api_provider="firstParty",
            auth_method="RAW-METHOD",
            subscription_type="RAW-PLAN",
            api_key_source=None,
        )
        fields = lm.readiness_fields(status, ("subscription", "first_party_login"), "firstParty")
        assert "RAW" not in json.dumps(fields)
        assert set(fields) <= lm.EVIDENCE_KEYS


class TestInferencePredicates:
    """The L1 / L2 success predicate, one broken part at a time."""

    def test_complete_success(self) -> None:
        fields = lm.assert_inference_success(run_ok(), "claude-haiku-4-5")
        assert fields["billing_mode"] == "subscription"
        assert fields["billing_state"] == "subscription"
        assert fields["billing_label_seen"] is True
        assert fields["requested_model"] == "claude-haiku-4-5"
        assert fields["effective_model"] == "claude-haiku-4-5-20251001"
        assert fields["est_cost_usd"] == 0.001

    @pytest.mark.parametrize(
        ("overrides", "expected"),
        [
            ({"exception": RuntimeError("x")}, O.INCONCLUSIVE),
            ({"events": []}, O.INCONCLUSIVE),
            ({"output": None}, O.OUTPUT_MISSING),
            ({"output": {"answer": "  "}}, O.OUTPUT_MISSING),
            ({"output": {"other": "x"}}, O.OUTPUT_MISSING),
            (
                {"events": [{"type": "agent_completed", "data": {"billing_mode": "unknown"}}]},
                O.BILLING_NOT_SUBSCRIPTION,
            ),
            (
                {"events": [{"type": "agent_completed", "data": {"billing_mode": "metered_api"}}]},
                O.BILLING_NOT_SUBSCRIPTION,
            ),
            ({"events": [{"type": "agent_completed", "data": {}}]}, O.BILLING_NOT_SUBSCRIPTION),
            (
                {"usage": {"billing": {"state": "metered_api", "breakdown": {"metered_api": 1}}}},
                O.BILLING_AGGREGATE_MISMATCH,
            ),
            (
                {"usage": {"billing": {"breakdown": {"subscription": 1, "metered_api": 1}}}},
                O.BILLING_AGGREGATE_MISMATCH,
            ),
            ({"usage": {}}, O.BILLING_AGGREGATE_MISMATCH),
            ({"usage": None}, O.BILLING_AGGREGATE_MISMATCH),
            ({"effective_model": ""}, O.EFFECTIVE_MODEL_MISSING),
            ({"effective_model": None}, O.EFFECTIVE_MODEL_MISSING),
            ({"total_cost_usd": None}, O.UNPRICED_MODEL_LABEL_UNEXERCISED),
            ({"total_cost_usd": 0.0}, O.UNPRICED_MODEL_LABEL_UNEXERCISED),
            ({"console_text": ""}, O.BILLING_LABEL_MISSING),
            ({"console_text": "Total: $0.0010"}, O.BILLING_LABEL_MISSING),
        ],
    )
    def test_each_failure_is_one_fixed_outcome(
        self, overrides: dict[str, Any], expected: lm.Outcome
    ) -> None:
        with raises_outcome(expected):
            lm.assert_inference_success(run_ok(**overrides), "claude-haiku-4-5")

    def test_failure_records_never_carry_free_text(self) -> None:
        with pytest.raises(lm.HarnessFailure) as info:
            lm.assert_inference_success(
                run_ok(console_text="", fields={"env_names_set": ["ANTHROPIC_API_KEY"]}),
                "claude-haiku-4-5",
            )
        assert set(info.value.extra) <= lm.EVIDENCE_KEYS


def outcome_of(result: lm.SessionResult) -> lm.Outcome:
    return result.results[0].outcome


@pytest.mark.claude_auth_readiness_mocked
class TestRealInferenceAdapters:
    """L1 / L3 / L2 through ``load_config`` -> ``ProviderRegistry`` -> ``WorkflowEngine``."""

    # -- happy path and reachability ------------------------------------------------------
    def test_full_session_reaches_the_real_engine_registry_and_provider(self, stack: Stack) -> None:
        seen: dict[str, dict[str, str | None]] = {"L1": {}, "L3": {}, "L2": {}}
        transports = [
            stack.script(sdk_frames(), on_connect=env_recorder(seen["L1"])),
            stack.script(
                sdk_frames(error="authentication_failed", is_error=True, status=401),
                on_connect=env_recorder(seen["L3"]),
            ),
            stack.script(sdk_frames(), on_connect=env_recorder(seen["L2"])),
        ]
        result = stack.session()
        assert result.succeeded, result.primary_failure
        assert [r.outcome for r in result.results] == [O.OK, O.OK, O.INVALID_KEY, O.OK]
        lm.finalize(result)
        # Every session was a real SDK client over a fake transport, and the real engine
        # rendered and sent one prompt in each.
        assert stack.consumed == 3
        assert all(t.connect_calls == 1 and len(t.user_messages) == 1 for t in transports)
        assert "What is Conductor" not in json.dumps(transports[0].user_messages)  # our question
        assert lm.LIVE_QUESTION in json.dumps(transports[0].user_messages)
        # Auth-status probes: L0 once; L1 and L2 twice each (registry validation + execute);
        # L3 (auto with a key) never.
        assert len(stack.probe.envs) == 5
        # The canary is in the process environment only for L3 and L2.
        assert seen["L1"]["key"] is None
        assert seen["L3"]["key"] == CANARY and seen["L2"]["key"] == CANARY
        assert "ANTHROPIC_API_KEY" not in os.environ
        assert stack.hits == []

    def test_evidence_of_a_full_session_is_complete_and_sanitized(self, stack: Stack) -> None:
        stack.script(sdk_frames())
        stack.script(sdk_frames(error="authentication_failed", is_error=True, status=401))
        stack.script(sdk_frames())
        result = stack.session()
        l1 = record_for(result.evidence, "L1")
        assert l1["billing_mode"] == "subscription" and l1["billing_state"] == "subscription"
        assert l1["billing_label_seen"] is True
        assert l1["requested_model"] == "claude-haiku-4-5"
        assert l1["effective_model"] == "claude-haiku-4-5-20251001"
        assert isinstance(l1["est_cost_usd"], float) and l1["est_cost_usd"] > 0
        assert l1["env_names_set"] == []
        l3 = record_for(result.evidence, "L3")
        assert l3["outcome"] == "invalid_key" and l3["env_names_set"] == ["ANTHROPIC_API_KEY"]
        assert l3["exception_class"] == "ProviderError"
        assert record_for(result.evidence, "L2")["env_names_set"] == ["ANTHROPIC_API_KEY"]
        assert CANARY not in json.dumps(result.evidence)

    # -- L1 ------------------------------------------------------------------------------
    def test_l1_output_present_but_billing_mode_wrong(self, stack: Stack) -> None:
        stack.probe.payload = without(LOGIN_PAYLOAD, "subscriptionType")
        stack.script(sdk_frames())
        result, records = stack.run_case(S.L1)
        assert outcome_of(result) is O.BILLING_NOT_SUBSCRIPTION
        assert not result.succeeded
        assert record_for(records, "L1")["outcome"] == "billing_not_subscription"

    def test_l1_aggregate_billing_wrong(self, stack: Stack) -> None:
        from conductor.engine.workflow import WorkflowEngine

        real = WorkflowEngine.get_execution_summary

        def metered(self: Any) -> dict[str, Any]:
            summary = real(self)
            summary["usage"] = {
                **summary["usage"],
                "billing": {"state": "metered_api", "breakdown": {"metered_api": 1}},
            }
            return summary

        stack.monkeypatch.setattr(WorkflowEngine, "get_execution_summary", metered)
        stack.script(sdk_frames())
        result, _ = stack.run_case(S.L1)
        assert outcome_of(result) is O.BILLING_AGGREGATE_MISMATCH

    def test_l1_label_missing(self, stack: Stack) -> None:
        stack.monkeypatch.setattr(
            "conductor.cli.run.display_usage_summary", lambda *args, **kwargs: None
        )
        stack.script(sdk_frames())
        result, records = stack.run_case(S.L1)
        assert outcome_of(result) is O.BILLING_LABEL_MISSING
        assert "billing_label_seen" not in record_for(records, "L1")

    def test_l1_unpriced_model_fails(self, stack: Stack) -> None:
        stack.script(sdk_frames(model="claude-unpriced-model-9"))
        result, _ = stack.run_case(S.L1)
        assert outcome_of(result) is O.UNPRICED_MODEL_LABEL_UNEXERCISED

    def test_l1_provider_error_is_inconclusive_with_its_class(self, stack: Stack) -> None:
        stack.script(sdk_frames(is_error=True, status=500))
        result, records = stack.run_case(S.L1)
        assert outcome_of(result) is O.INCONCLUSIVE
        assert record_for(records, "L1")["exception_class"] == "ProviderError"

    # -- L3 ------------------------------------------------------------------------------
    def test_l3_typed_invalid_key(self, stack: Stack) -> None:
        stack.script(sdk_frames(error="authentication_failed", is_error=True, status=401))
        result, records = stack.run_case(S.L3)
        assert outcome_of(result) is O.INVALID_KEY
        assert record_for(records, "L3")["attempted_quota_execution"] is True

    def test_l3_success_is_fallback_not_success(self, stack: Stack) -> None:
        stack.script(sdk_frames())
        result, _ = stack.run_case(S.L3)
        assert outcome_of(result) is O.FELL_BACK_TO_LOGIN
        assert not result.succeeded

    def test_l3_generic_non_retryable_is_inconclusive(self, stack: Stack) -> None:
        stack.script(sdk_frames(is_error=True, status=400))
        result, _ = stack.run_case(S.L3)
        assert outcome_of(result) is O.INCONCLUSIVE

    def test_l3_error_text_alone_is_never_a_classification(self, stack: Stack) -> None:
        """Text that *says* authentication failed, with no typed signal, stays inconclusive."""
        stack.script(
            sdk_frames(
                text="authentication_failed 401 invalid x-api-key", is_error=True, status=400
            )
        )
        result, _ = stack.run_case(S.L3)
        assert outcome_of(result) is O.INCONCLUSIVE

    def test_l3_timeout_returns_an_observation_and_scans_the_canary(self, stack: Stack) -> None:
        stack.script(None)  # never answers
        result, records = stack.run_case(S.L3, timeouts={S.L3: 0.05})
        assert outcome_of(result) is O.INCONCLUSIVE
        record = record_for(records, "L3")
        assert record["exception_class"] == "TimeoutError"
        # a timeout is an ordinary outcome: the scan is complete and no result exists
        assert record["interrupted"] == "none" and record["secondary_findings"] == []
        assert scan_of(record)[lm.REQUIRED_STREAMS.index("workflow_result")] == (
            "workflow_result:not_available"
        )
        assert lm.scan_is_clean_and_complete(record["canary_scan"], "L3")

    def test_l3_timeout_with_a_leak_is_a_canary_failure_not_inconclusive(
        self, stack: Stack
    ) -> None:
        stack.script(None, on_connect=canary_logger)
        result, records = stack.run_case(S.L3, timeouts={S.L3: 0.05})
        assert outcome_of(result) is O.CANARY_LEAK
        record = record_for(records, "L3")
        assert record["adapter_outcome"] == "inconclusive"  # what the case itself produced
        assert record["exception_class"] == "TimeoutError"
        assert "logs:leak" in scan_of(record)
        assert CANARY not in json.dumps(records)

    # -- L2 ------------------------------------------------------------------------------
    def test_l2_complete_success(self, stack: Stack) -> None:
        stack.script(sdk_frames())
        result, records = stack.run_case(S.L2)
        assert result.succeeded
        l2 = record_for(records, "L2")
        assert l2["billing_mode"] == "subscription" and l2["billing_label_seen"] is True

    def test_l2_canary_used_is_a_blocker(self, stack: Stack) -> None:
        stack.script(sdk_frames(error="authentication_failed", is_error=True, status=401))
        result, _ = stack.run_case(S.L2)
        assert outcome_of(result) is O.CANARY_USED_IN_L2
        assert O.CANARY_USED_IN_L2 in lm.SAFETY_OUTCOMES

    def test_l2_canary_leak_is_detected_in_the_log_stream(self, stack: Stack) -> None:
        stack.script(sdk_frames(), on_connect=canary_logger)
        result, _ = stack.run_case(S.L2)
        assert outcome_of(result) is O.CANARY_LEAK

    def test_l2_billing_mismatch(self, stack: Stack) -> None:
        stack.probe.payload = without(LOGIN_PAYLOAD, "subscriptionType")
        stack.script(sdk_frames())
        result, _ = stack.run_case(S.L2)
        assert outcome_of(result) is O.BILLING_NOT_SUBSCRIPTION

    def test_l2_label_mismatch(self, stack: Stack) -> None:
        stack.monkeypatch.setattr(
            "conductor.cli.run.display_usage_summary", lambda *args, **kwargs: None
        )
        stack.script(sdk_frames())
        result, _ = stack.run_case(S.L2)
        assert outcome_of(result) is O.BILLING_LABEL_MISSING

    # -- exceptions still produce a scanned observation ----------------------------------
    @pytest.mark.parametrize("case", [S.L1, S.L3, S.L2])
    def test_adapter_exception_is_scanned_before_the_state_machine_decides(
        self, stack: Stack, case: lm.Case
    ) -> None:
        stack.script(sdk_frames(), on_connect=raising(RuntimeError(f"cannot connect {CANARY}")))
        result, records = stack.run_case(case)
        assert outcome_of(result) is O.CANARY_LEAK  # not case_failed / inconclusive
        assert CANARY not in json.dumps(records)

    def test_adapter_exception_without_a_leak_keeps_its_class(self, stack: Stack) -> None:
        stack.script(sdk_frames(), on_connect=raising(RuntimeError("cannot connect")))
        result, records = stack.run_case(S.L1)
        assert outcome_of(result) is O.INCONCLUSIVE
        assert record_for(records, "L1")["exception_class"] == "ProviderError"

    # -- H21: a secret-like DEBUG record stays private --------------------------------------
    def test_an_evicted_log_record_naming_the_canary_is_still_a_leak(self, stack: Stack) -> None:
        """The bounded buffer may drop a record; the emit-time check has already seen it."""
        import functools

        stack.monkeypatch.setattr(
            lm, "_BufferHandler", functools.partial(lm._BufferHandler, max_records=1)
        )

        def flood() -> None:
            logging.getLogger(SDK_LOGGER).debug("leaked key %s", CANARY)
            for _ in range(5):
                logging.getLogger(SDK_LOGGER).debug("innocent")

        stack.script(sdk_frames(), on_connect=flood)
        result, records = stack.run_case(S.L2)
        assert outcome_of(result) is O.CANARY_LEAK
        assert "logs:leak" in scan_of(record_for(records, "L2"))
        assert CANARY not in json.dumps(records)

    def test_a_secret_like_debug_record_reaches_neither_pytest_nor_the_evidence(
        self, stack: Stack, caplog: pytest.LogCaptureFixture
    ) -> None:
        probe = RecordingHandler()
        root = logging.getLogger()
        root.addHandler(probe)
        seen: dict[str, int] = {}

        def noisy() -> None:
            seen["root_level"] = root.level
            logging.getLogger(SDK_LOGGER).debug(
                "Skipping non-JSON line from CLI stdout: %s", SECRET
            )
            logging.getLogger("conductor.providers.claude_agent_sdk").debug("p %s", SECRET)

        level_before = root.level
        stack.script(sdk_frames(), on_connect=noisy)
        try:
            result, records = stack.run_case(S.L2)
        finally:
            root.removeHandler(probe)
        assert result.succeeded
        assert seen["root_level"] == level_before  # the root logger was not raised during the case
        assert [r for r in probe.records if SECRET in r.getMessage()] == []
        assert SECRET not in caplog.text  # pytest's captured-log section
        assert SECRET not in json.dumps(records)  # nor the future saved evidence
        assert stack.capfd is not None and SECRET not in "".join(stack.capfd.readouterr())
        assert stack.hits == []

    # -- H23: the aggregate billing state, per case ---------------------------------------
    @staticmethod
    def _mixed_aggregate(stack: Stack, on_call: int) -> dict[str, int]:
        """Make the ``on_call``-th execution summary report a mixed billing aggregate."""
        from conductor.engine.workflow import WorkflowEngine

        real = WorkflowEngine.get_execution_summary
        calls = {"n": 0}

        def summary(self: Any) -> dict[str, Any]:
            calls["n"] += 1
            out = real(self)
            if calls["n"] == on_call:
                out["usage"] = {
                    **out["usage"],
                    "billing": {
                        "state": "mixed",
                        "breakdown": {"subscription": 1, "metered_api": 1},
                    },
                }
            return out

        stack.monkeypatch.setattr(WorkflowEngine, "get_execution_summary", summary)
        return calls

    def test_l2_aggregate_billing_mismatch_fails_l2_while_l1_is_healthy(self, stack: Stack) -> None:
        stack.script(sdk_frames())  # L1
        stack.script(sdk_frames())  # L2
        calls = self._mixed_aggregate(stack, on_call=2)
        result = stack.run_cases((S.L1, S.L2))
        assert calls["n"] == 2  # one summary per case, so the second is L2's
        assert [r.outcome for r in result.results] == [O.OK, O.BILLING_AGGREGATE_MISMATCH]
        assert record_for(stack.records, "L1")["billing_state"] == "subscription"
        assert record_for(stack.records, "L2")["outcome"] == "billing_aggregate_mismatch"
        assert "billing_state" not in record_for(stack.records, "L2")
        assert stack.hits == []

    def test_l1_aggregate_billing_mismatch_fails_l1_while_l2_is_healthy(self, stack: Stack) -> None:
        stack.script(sdk_frames())  # L1
        stack.script(sdk_frames())  # L2 (never reached: L1 failed)
        self._mixed_aggregate(stack, on_call=1)
        result = stack.run_cases((S.L1, S.L2))
        assert [r.outcome for r in result.results] == [
            O.BILLING_AGGREGATE_MISMATCH,
            O.NOT_EXECUTED_AFTER_L1_FAILURE,
        ]
        assert stack.consumed == 1
        assert stack.hits == []

    # -- H18 through the real adapter: the original interrupt, everything restored ---------
    @pytest.mark.parametrize(("factory", "kind"), INTERRUPTS)
    @pytest.mark.parametrize(("canary_in", "descendant", "secondary"), FINDING_ROWS)
    def test_an_interrupt_at_the_engine_is_reraised_unchanged_and_everything_is_restored(
        self,
        stack: Stack,
        factory: type[BaseException],
        kind: str,
        canary_in: str | None,
        descendant: bool,
        secondary: list[str],
    ) -> None:
        import claude_agent_sdk

        from conductor.engine.workflow import WorkflowEngine

        original = factory()
        runs: list[str] = []

        async def interrupted(self: Any, inputs: Any) -> Any:
            runs.append("run")
            if canary_in is not None:
                canary_logger()
            raise original

        stack.monkeypatch.setattr(WorkflowEngine, "run", interrupted)
        env_before = dict(os.environ)
        loggers_before = private_logger_state()

        def read() -> dict[int, tuple[int, str]]:
            return {os.getpid() + 1: (os.getpid(), "leaky")} if descendant and runs else {}

        with pytest.raises(type(original)) as info:
            stack.run_cases((S.L1, S.L3, S.L2), read_table=read)
        assert info.value is original  # the very object, never converted
        assert not isinstance(info.value, (lm.HarnessFailure, pytest.fail.Exception))
        record = record_for(stack.records, "L1")
        assert record["outcome"] == "interrupted" and record["interrupted"] == kind
        assert record["secondary_findings"] == secondary
        assert ("logs:leak" in scan_of(record)) == (canary_in is not None)
        assert len(scan_of(record)) == 8
        assert CANARY not in json.dumps(stack.records)
        # nothing later ran, and the state machine says so
        assert runs == ["run"] and stack.consumed == 0
        run_level = next(r for r in stack.records if "case" not in r)
        assert run_level["not_executed"] == (
            "L3:not_executed_after_interrupt,L2:not_executed_after_interrupt"
        )
        # restoration: environment, observer and logging
        assert dict(os.environ) == env_before
        assert claude_agent_sdk.ClaudeSDKClient.receive_response is stack.receive_original
        assert private_logger_state() == loggers_before
        assert stack.hits == []

    def test_a_real_task_cancellation_with_a_leak_is_recorded_then_reraised(
        self, stack: Stack
    ) -> None:
        adapters = stack.adapters()
        stack.script(None, on_connect=canary_logger)

        async def go() -> None:
            task = asyncio.ensure_future(adapters.workflow.execute(stack.variants()[S.L2]))
            for _ in range(20):
                await asyncio.sleep(0)
            task.cancel()
            await task

        loggers_before = private_logger_state()
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(go())
        findings = adapters.board.for_case(S.L2)
        assert findings.canary_leak and "logs:leak" in findings.entries
        assert "ANTHROPIC_API_KEY" not in os.environ
        assert private_logger_state() == loggers_before
        assert stack.hits == []

    def test_a_real_task_cancellation_without_a_leak_propagates_unchanged(
        self, stack: Stack
    ) -> None:
        adapters = stack.adapters()
        stack.script(None)

        async def go() -> None:
            task = asyncio.ensure_future(adapters.workflow.execute(stack.variants()[S.L2]))
            for _ in range(20):
                await asyncio.sleep(0)
            task.cancel()
            await task

        with pytest.raises(asyncio.CancelledError):
            asyncio.run(go())
        assert not adapters.board.for_case(S.L2).canary_leak
        assert "ANTHROPIC_API_KEY" not in os.environ

    def test_a_keyboard_interrupt_escapes_asyncio_run_and_no_later_case_runs(
        self, stack: Stack
    ) -> None:
        original = KeyboardInterrupt()
        stack.script(sdk_frames(), on_connect=raising(original))
        stack.script(sdk_frames())
        with pytest.raises(KeyboardInterrupt) as info:
            stack.run_cases((S.L1, S.L2))
        assert not isinstance(info.value, lm.HarnessFailure)
        assert stack.consumed == 1  # L2's session was never opened
        assert record_for(stack.records, "L1")["outcome"] == "interrupted"

    # -- H25: authentication probes are reproduced, not avoided ------------------------------
    def test_probe_counts_per_case(self, stack: Stack) -> None:
        expected = {S.L1: 2, S.L3: 0, S.L2: 2}
        for case, count in expected.items():
            stack.probe.envs.clear()
            stack.probe.sites.clear()
            frames = (
                sdk_frames(error="authentication_failed", is_error=True, status=401)
                if case is S.L3
                else sdk_frames()
            )
            stack.script(frames)
            stack.run_case(case)
            assert len(stack.probe.envs) == count, case
        stack.probe.envs.clear()
        stack.probe.sites.clear()
        probe_l0(stack)
        assert len(stack.probe.envs) == 1  # L0, and therefore the readiness-only check
        assert stack.probe.sites == ["direct"]

    def test_official_total_is_five_in_a_fixed_order_and_probes_are_not_quota(
        self, stack: Stack
    ) -> None:
        stack.script(sdk_frames())
        stack.script(sdk_frames(error="authentication_failed", is_error=True, status=401))
        stack.script(sdk_frames())
        result = stack.session()
        assert result.succeeded
        assert len(stack.probe.envs) == 5
        assert stack.probe.sites == ["direct", "validation", "execution", "validation", "execution"]
        assert result.quota_attempts == 3 <= lm.DEFAULT_QUOTA_CEILING  # probes are not counted


def leak_streams(stack: Stack, variant_case: lm.Case = S.L2) -> list[str]:
    """Run the real workflow adapter once and return the names of the streams holding the canary."""
    adapters = stack.adapters()
    observed = asyncio.run(adapters.workflow.execute(stack.variants()[variant_case]))
    assert set(observed.streams) == set(lm.REQUIRED_STREAMS)  # every category is supplied
    return lm.scan_streams(CANARY, observed.streams)


@pytest.mark.claude_auth_readiness_mocked
class TestEveryRequiredStreamIsScanned:
    """H22: a canary planted in exactly one stream is found in exactly that stream."""

    def test_stream_names_are_the_honest_ones_in_order(self) -> None:
        assert lm.REQUIRED_STREAMS == (
            "stdout_stderr",
            "console",
            "logs",
            "exceptions",
            "events",
            "workflow_result",
            "evidence",
            "tmp_files",
        )
        retired = {"capfd", "capsys", "caplog", "raw_response"}
        assert not retired & set(lm.REQUIRED_STREAMS)
        assert not retired & lm.EVIDENCE_KEYS
        constants = {
            node.value
            for node in ast.walk(module_ast())
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert not retired & constants  # nor in any message or fixed string of the module

    def test_clean_run_has_no_hit_in_any_stream(self, stack: Stack) -> None:
        stack.script(sdk_frames())
        assert leak_streams(stack) == []

    def test_file_descriptor_writes_reach_stdout_stderr(self, stack: Stack) -> None:
        """Text written straight to fd 1 and fd 2 (below ``sys.stdout``) is what ``capfd`` sees."""

        def leak() -> None:
            os.write(1, f"out {CANARY}\n".encode())
            os.write(2, f"err {CANARY}\n".encode())

        stack.script(sdk_frames(), on_connect=leak)
        assert leak_streams(stack) == ["stdout_stderr"]

    def test_python_level_prints_reach_stdout_stderr(self, stack: Stack) -> None:
        def leak() -> None:
            print(f"out {CANARY}")
            print(f"err {CANARY}", file=sys.stderr)

        stack.script(sdk_frames(), on_connect=leak)
        assert leak_streams(stack) == ["stdout_stderr"]

    def test_console_buffer_is_scanned(self, stack: Stack) -> None:
        def loud(usage: object, console: Any = None) -> None:
            console.print(f"total {CANARY}")

        stack.monkeypatch.setattr("conductor.cli.run.display_usage_summary", loud)
        stack.script(sdk_frames())
        assert leak_streams(stack) == ["console"]

    def test_private_log_records_are_scanned(self, stack: Stack) -> None:
        stack.script(sdk_frames(), on_connect=canary_logger)
        assert leak_streams(stack) == ["logs"]

    def test_a_log_record_from_the_provider_logger_is_scanned(self, stack: Stack) -> None:
        def leak() -> None:
            logging.getLogger("conductor.providers.claude_agent_sdk").debug("k %s", CANARY)

        stack.script(sdk_frames(), on_connect=leak)
        assert leak_streams(stack) == ["logs"]

    def test_files_under_tmp_path_are_scanned(self, stack: Stack) -> None:
        def write() -> None:
            (stack.tmp_path / "leak.txt").write_text(CANARY)

        stack.script(sdk_frames(), on_connect=write)
        assert leak_streams(stack) == ["tmp_files"]

    def test_exception_chain_is_scanned(self, stack: Stack) -> None:
        stack.script(sdk_frames(), on_connect=raising(RuntimeError(f"cannot connect {CANARY}")))
        assert "exceptions" in leak_streams(stack)

    def test_workflow_result_and_events_are_scanned(self, stack: Stack) -> None:
        echoed = json.dumps({"answer": f"echo {CANARY}"})
        stack.script(sdk_frames(text=echoed))
        assert {"events", "workflow_result"} <= set(leak_streams(stack))

    def test_workflow_result_is_the_value_the_engine_returned(self, stack: Stack) -> None:
        """Derived from ``engine.run``'s return value, not from an inaccessible provider field."""
        from conductor.engine.workflow import WorkflowEngine

        real = WorkflowEngine.run

        async def planted(self: Any, inputs: Any) -> Any:
            out = await real(self, inputs)
            return {**out, "answer": f"planted {CANARY}"}

        stack.monkeypatch.setattr(WorkflowEngine, "run", planted)
        stack.script(sdk_frames())
        adapters = stack.adapters()
        observed = asyncio.run(adapters.workflow.execute(stack.variants()[S.L2]))
        assert observed.streams["workflow_result"] == observed.output
        assert lm.scan_streams(
            CANARY, {"workflow_result": observed.streams["workflow_result"]}
        ) == ["workflow_result"]

    def test_no_result_is_marked_not_available_and_still_complete(self, stack: Stack) -> None:
        stack.script(sdk_frames(is_error=True, status=500))
        adapters = stack.adapters()
        observed = asyncio.run(adapters.workflow.execute(stack.variants()[S.L2]))
        assert observed.streams["workflow_result"] is lm.NOT_AVAILABLE
        findings = adapters.board.for_case(S.L2)
        assert findings.entries[lm.REQUIRED_STREAMS.index("workflow_result")] == (
            "workflow_result:not_available"
        )
        assert not findings.incomplete


@pytest.mark.claude_auth_readiness_mocked
class TestPerCaseIsolation:
    """Nothing from L0 / L1 / L3 / L2 bleeds into another case."""

    def test_environment_and_observer_are_restored_after_a_full_session(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "route-token-value")
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        before = dict(os.environ)
        stack.script(sdk_frames())
        stack.script(sdk_frames(error="authentication_failed", is_error=True, status=401))
        stack.script(sdk_frames())
        result = stack.session()
        assert result.succeeded
        assert dict(os.environ) == before
        import claude_agent_sdk

        assert claude_agent_sdk.ClaudeSDKClient.receive_response is stack.receive_original

    def test_each_case_sees_its_own_environment_and_the_route_scrub(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "route-token-value")
        seen: list[dict[str, str | None]] = [{}, {}, {}]

        def route_probe(target: dict[str, str | None]) -> Callable[[], None]:
            def record() -> None:
                target["key"] = os.environ.get("ANTHROPIC_API_KEY")
                target["token"] = os.environ.get("ANTHROPIC_AUTH_TOKEN")
                target["home"] = os.environ.get("HOME")

            return record

        stack.script(sdk_frames(), on_connect=route_probe(seen[0]))
        stack.script(
            sdk_frames(error="authentication_failed", is_error=True, status=401),
            on_connect=route_probe(seen[1]),
        )
        stack.script(sdk_frames(), on_connect=route_probe(seen[2]))
        assert stack.session().succeeded
        assert [s["key"] for s in seen] == [None, CANARY, CANARY]
        assert all(s["token"] is None for s in seen)
        assert all(s["home"] == os.environ.get("HOME") for s in seen)  # real HOME kept

    def test_failure_in_one_case_still_restores_everything(self, stack: Stack) -> None:
        before = dict(os.environ)
        loggers_before = private_logger_state()
        stack.script(sdk_frames(), on_connect=raising(RuntimeError("boom")))
        result, _ = stack.run_case(S.L3)
        assert outcome_of(result) is O.INCONCLUSIVE
        assert private_logger_state() == loggers_before
        assert dict(os.environ) == before
        import claude_agent_sdk

        assert claude_agent_sdk.ClaudeSDKClient.receive_response is stack.receive_original

    def test_event_log_and_run_records_stay_under_tmp_path(self, stack: Stack) -> None:
        stack.script(sdk_frames())
        stack.run_case(S.L1)
        assert any(stack.tmp_path.rglob("*.yaml"))
        assert stack.hits == []


@pytest.mark.usefixtures("gates_on")
class TestOfficialFlag:
    def test_official_requires_a_clean_tree_a_pass_and_zero_skips(self, tmp_path: Path) -> None:
        for dirty, expected in ((False, True), (True, False)):
            plugin = lm.ZeroSkipPlugin()
            config = make_config()
            config.pluginmanager.register(plugin, lm.ZERO_SKIP_PLUGIN_NAME)
            fake = FakeAdapterSet()
            clock = Clock()
            result = asyncio.run(
                lm.run_official_session(
                    config,
                    tmp_path,
                    fake.as_set(),
                    readiness_check=lambda: None,
                    prereq_check=lambda: "bundled",
                    grace_s=0.0,
                    sleep=clock.sleep,
                    git_state=lambda dirty=dirty: (GIT_SHA, dirty),
                    facts=lambda: dict(FACTS),
                )
            )
            assert result.succeeded
            assert plugin.official is expected


class TestFixtureNameAstCheck:
    """H12 tightening: only a module-level fixture with the expected name satisfies it."""

    NAMES = ("_stub_claude_auth_readiness",)

    def test_module_level_fixture_is_accepted(self) -> None:
        source = (
            "import pytest\n\n@pytest.fixture(autouse=True)\n"
            "def _stub_claude_auth_readiness():\n    pass\n"
        )
        assert missing_module_level_fixtures(source, self.NAMES) == []

    def test_nested_function_with_the_same_name_is_rejected(self) -> None:
        source = (
            "import pytest\n\ndef outer():\n"
            "    @pytest.fixture(autouse=True)\n"
            "    def _stub_claude_auth_readiness():\n        pass\n"
        )
        assert missing_module_level_fixtures(source, self.NAMES) == list(self.NAMES)

    def test_method_with_the_same_name_is_rejected(self) -> None:
        source = (
            "import pytest\n\nclass C:\n"
            "    @pytest.fixture\n"
            "    def _stub_claude_auth_readiness(self):\n        pass\n"
        )
        assert missing_module_level_fixtures(source, self.NAMES) == list(self.NAMES)

    def test_undecorated_module_level_function_is_not_a_fixture(self) -> None:
        source = "def _stub_claude_auth_readiness():\n    pass\n"
        assert missing_module_level_fixtures(source, self.NAMES) == list(self.NAMES)

    def test_absent_name_is_reported(self) -> None:
        assert missing_module_level_fixtures("x = 1\n", self.NAMES) == list(self.NAMES)


def enclosing_functions(tree: ast.AST, callee: str) -> set[str]:
    """Names of the (innermost) functions that *call* ``callee``."""
    holders: set[str] = set()

    def visit(node: ast.AST, current: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            inner = (
                child.name if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) else current
            )
            if isinstance(child, ast.Call):
                func = child.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                if name == callee and inner is not None:
                    holders.add(inner)
            visit(child, inner)

    visit(tree, None)
    return holders


def adapter_class_nodes() -> dict[str, ast.ClassDef]:
    return {
        node.name: node
        for node in module_ast().body
        if isinstance(node, ast.ClassDef) and node.name.startswith("Real")
    }


class TestAdapterStructure:
    """Static guards on the real adapters (gate, isolation, process table, patch scopes)."""

    @pytest.mark.parametrize(("cls", "method"), list(lm.iter_adapter_process_methods()))
    def test_every_adapter_entry_point_guards_itself_first(self, cls: str, method: str) -> None:
        node = next(
            n
            for n in adapter_class_nodes()[cls].body
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == method
        )
        assert [ast.unparse(s) for s in node.body[:2]] == [
            "require_live_optin(self._config)",
            "assert_live_isolation(self._tmp_path)",
        ]

    def test_adapter_entry_points_are_all_listed(self) -> None:
        listed = {cls for cls, _ in lm.iter_adapter_process_methods()}
        assert listed == set(adapter_class_nodes())

    def test_configured_adapters_guards_itself_first(self) -> None:
        node = module_level_functions(module_ast())["configured_adapters"]
        body = node.body[1:] if isinstance(node.body[0], ast.Expr) else node.body
        assert [ast.unparse(s) for s in body[:2]] == [
            "require_live_optin(pytestconfig)",
            "assert_live_isolation(tmp_path)",
        ]
        assert list(inspect.signature(lm.configured_adapters).parameters) == [
            "pytestconfig",
            "tmp_path",
            "monkeypatch",
            "capfd",
            "canary",
        ]

    def test_only_the_guarded_snapshot_reads_the_process_table(self) -> None:
        """D14: ``read_ps_table`` stays public and unguarded; no adapter may touch it."""
        tree = module_ast()
        assert enclosing_functions(tree, "read_ps_table") == {"descendant_snapshot"}
        # no reference at all (a call, an alias, a default argument, a callback) in an adapter
        for name, node in adapter_class_nodes().items():
            for ref in ast.walk(node):
                text = ast.unparse(ref) if isinstance(ref, ast.Name | ast.Attribute) else ""
                assert "read_ps_table" not in text, (name, text)
        # ... anywhere but its own definition and the one guarded snapshot
        references = {
            func.name
            for func in ast.walk(tree)
            if isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
            for ref in ast.walk(func)
            if isinstance(ref, ast.Name) and ref.id == "read_ps_table"
        }
        assert references == {"descendant_snapshot"}
        # ... and no adapter reaches any process-spawning helper itself.
        forbidden = {
            "read_ps_table",
            "_run_owned_subprocess",
            "Popen",
            "subprocess.Popen",
            "subprocess.run",
            "subprocess.check_output",
            "subprocess.check_call",
            "asyncio.create_subprocess_exec",
            "asyncio.create_subprocess_shell",
            "os.system",
            "os.posix_spawn",
            "os.kill",
            "os.killpg",
        }
        for name, node in adapter_class_nodes().items():
            for call in ast.walk(node):
                if isinstance(call, ast.Call):
                    assert ast.unparse(call.func) not in forbidden, (name, ast.unparse(call.func))
        # the owned-subprocess helper is used only by the helpers that own their process
        assert enclosing_functions(tree, "_run_owned_subprocess") == {
            "_default",
            "read_ps_table",
        }

    def test_adapters_patch_only_through_an_independent_context(self) -> None:
        """No ``self._monkeypatch.setenv/delenv/setattr`` outside a ``.context()`` scope."""
        for name in ("RealReadinessAdapter", "RealWorkflowAdapter", "RealObserverInstaller"):
            node = adapter_class_nodes()[name]
            source = ast.unparse(node)
            assert "self._monkeypatch.context()" in source, name
            for direct in ("setenv", "delenv", "setattr", "setitem", "delitem", "chdir"):
                assert f"self._monkeypatch.{direct}(" not in source, (name, direct)

    def test_both_capturing_adapters_scan_on_every_exit_path(self) -> None:
        """The scan sits in a ``finally`` that also runs when a non-``Exception`` propagates."""
        for name in ("RealReadinessAdapter", "RealWorkflowAdapter"):
            source = ast.unparse(adapter_class_nodes()[name])
            assert "except BaseException" in source and "finally:" in source, name
            assert "record_case_scan(" in source and "PrivateLogCapture(" in source, name
            after_handler = source.split("except BaseException")[1]
            assert "raise" in after_handler.split("finally:")[0], name  # bare re-raise

    def test_live_tests_request_capfd_but_never_capsys_too(self) -> None:
        """pytest refuses ``capfd`` and ``capsys`` together ("cannot use ... at the same time")."""
        for name in ("test_official_live_evidence", "test_readiness_probe_only"):
            params = list(inspect.signature(getattr(lm, name)).parameters)
            assert params == ["pytestconfig", "tmp_path", "monkeypatch", "capfd"], name
            assert not {"capfd", "capsys"} <= set(params)
            assert "caplog" not in params  # the live tests never use pytest's log capture

    # -- the tests below construct or call real adapters: tripwires are armed first (H24) ----
    def test_configured_adapters_construction_failure_is_adapters_not_wired(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        gates_on: None,
        boundary_hits: list[str],
    ) -> None:
        def broken(*args: object, **kwargs: object) -> None:
            raise RuntimeError("cannot build")

        monkeypatch.setattr(lm, "RealCliEvidenceAdapter", broken)
        with raises_outcome(O.ADAPTERS_NOT_WIRED):
            lm.configured_adapters(make_config(), tmp_path, monkeypatch, None, canary=CANARY)
        assert boundary_hits == []

    def test_configured_adapters_requires_the_gates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary_hits: list[str]
    ) -> None:
        monkeypatch.delenv(lm.GATE_ENV, raising=False)
        with pytest.raises(lm.LiveOptInError):
            lm.configured_adapters(make_config(), tmp_path, monkeypatch, None, canary=CANARY)
        assert boundary_hits == []

    def test_configured_adapters_rejects_a_malformed_canary(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        gates_on: None,
        boundary_hits: list[str],
    ) -> None:
        with raises_outcome(O.CANARY_SCAN_INCOMPLETE):
            lm.configured_adapters(
                make_config(), tmp_path, monkeypatch, None, canary="not-a-canary"
            )
        assert boundary_hits == []

    def test_configured_adapters_returns_the_five_real_adapters(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        gates_on: None,
        boundary_hits: list[str],
    ) -> None:
        adapters = lm.configured_adapters(make_config(), tmp_path, monkeypatch, None, canary=CANARY)
        assert isinstance(adapters.readiness, lm.RealReadinessAdapter)
        assert isinstance(adapters.workflow, lm.RealWorkflowAdapter)
        assert isinstance(adapters.cli, lm.RealCliEvidenceAdapter)
        assert isinstance(adapters.descendants, lm.RealDescendantAdapter)
        assert isinstance(adapters.observer, lm.RealObserverInstaller)
        assert adapters.board.canary == CANARY  # one ledger, shared with the case wrapper
        assert boundary_hits == []

    def test_constructing_the_adapter_set_enters_no_boundary_and_records_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        gates_on: None,
        boundary_hits: list[str],
    ) -> None:
        adapters = lm.configured_adapters(make_config(), tmp_path, monkeypatch, None, canary=CANARY)
        assert boundary_hits == []
        assert list(tmp_path.glob("workflow-*.yaml")) == []  # nothing written before a case runs
        assert all(not adapters.board.for_case(case).scan for case in lm.ORDER)

    def test_each_real_adapter_refuses_to_run_without_the_gates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary_hits: list[str]
    ) -> None:
        monkeypatch.delenv(lm.GATE_ENV, raising=False)
        config = make_config()
        board = lm.FindingsBoard(CANARY)
        readiness = lm.RealReadinessAdapter(
            config, tmp_path, monkeypatch, capfd=None, canary=CANARY, board=board
        )
        with pytest.raises(lm.LiveOptInError):
            asyncio.run(readiness.probe())
        workflow = lm.RealWorkflowAdapter(
            config, tmp_path, monkeypatch, capfd=None, canary=CANARY, board=board
        )
        variant = lm.CaseVariant(S.L1, "subscription", {}, lm.EnvPlan((), ()))
        with pytest.raises(lm.LiveOptInError):
            asyncio.run(workflow.execute(variant))
        with pytest.raises(lm.LiveOptInError):
            lm.RealDescendantAdapter(config, tmp_path).snapshot()
        with pytest.raises(lm.LiveOptInError):
            lm.RealCliEvidenceAdapter(config, tmp_path).resolve()
        with (
            pytest.raises(lm.LiveOptInError),
            lm.RealObserverInstaller(config, tmp_path, monkeypatch).observing(),
        ):
            pass
        assert boundary_hits == []
        assert not any(board.for_case(case).scan for case in lm.ORDER)  # refused before any scan


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=0)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class TestPrivateLogCapture:
    """H21 (iii)-(v): a private handler, a fixed logger set, no propagation, exact restoration."""

    def test_records_of_the_sdk_and_its_children_and_the_provider_are_captured(self) -> None:
        with lm.PrivateLogCapture(CANARY) as logs:
            logging.getLogger("claude_agent_sdk").debug("sdk %s", SECRET)
            logging.getLogger("claude_agent_sdk._internal.query").debug("child %s", SECRET)
            logging.getLogger("conductor.providers.claude_agent_sdk").info("provider %s", SECRET)
            logging.getLogger("other.library").debug("not-ours %s", SECRET)
        assert logs.text.count(SECRET) == 3 and "not-ours" not in logs.text
        assert not logs.leaked

    def test_nothing_reaches_the_root_logger_or_pytest_report_handlers(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        probe = RecordingHandler()
        root = logging.getLogger()
        root.addHandler(probe)
        level = root.level
        try:
            with lm.PrivateLogCapture(CANARY):
                assert root.level == level  # never raised, not even temporarily
                logging.getLogger("claude_agent_sdk").debug("dbg %s", SECRET)
                logging.getLogger("claude_agent_sdk").error("err %s", SECRET)  # not propagated
                logging.getLogger("conductor.providers.claude_agent_sdk").warning("w %s", SECRET)
                logging.getLogger("hermetic.other").debug("other %s", SECRET)  # root level filters
            assert root.level == level
        finally:
            root.removeHandler(probe)
        assert [r for r in probe.records if SECRET in r.getMessage()] == []
        assert SECRET not in caplog.text  # pytest's captured-log section

    @pytest.mark.parametrize(
        "exit_with",
        [None, RuntimeError("boom"), KeyboardInterrupt(), asyncio.CancelledError()],
        ids=["success", "failure", "interrupt", "cancellation"],
    )
    def test_level_handlers_propagation_and_disabled_are_restored_exactly(
        self, exit_with: BaseException | None
    ) -> None:
        odd_a = logging.getLogger("hermetic.priv.a")
        odd_b = logging.getLogger("hermetic.priv.b")
        keep = RecordingHandler()
        odd_a.setLevel(logging.ERROR)
        odd_a.propagate = True
        odd_a.addHandler(keep)
        odd_b.setLevel(logging.NOTSET)
        odd_b.propagate = False
        odd_b.disabled = True
        names = ("hermetic.priv.a", "hermetic.priv.b", *lm.PRIVATE_LOGGERS)
        before = {
            n: (lg.level, list(lg.handlers), lg.propagate, lg.disabled)
            for n in names
            for lg in [logging.getLogger(n)]
        }
        root_before = private_logger_state()["<root>"]
        try:
            try:
                with lm.PrivateLogCapture(CANARY, loggers=names) as logs:
                    assert all(logging.getLogger(n).level == logging.DEBUG for n in names)
                    assert all(logging.getLogger(n).propagate is False for n in names)
                    assert all(logging.getLogger(n).disabled is False for n in names)
                    odd_a.debug("captured %s", SECRET)
                    assert SECRET in logs.text
                    if exit_with is not None:
                        raise exit_with
            except BaseException as raised:
                assert raised is exit_with  # never swallowed, never replaced
            after = {
                n: (lg.level, list(lg.handlers), lg.propagate, lg.disabled)
                for n in names
                for lg in [logging.getLogger(n)]
            }
            assert after == before
            assert private_logger_state()["<root>"] == root_before
        finally:
            odd_a.removeHandler(keep)
            odd_a.setLevel(logging.NOTSET)
            odd_a.propagate = True
            odd_b.disabled = False
            odd_b.propagate = True

    def test_a_failure_while_entering_restores_what_was_already_changed(self) -> None:
        logger = logging.getLogger("hermetic.priv.enter")
        before = (logger.level, list(logger.handlers), logger.propagate, logger.disabled)
        bad_names = cast("Sequence[str]", ("hermetic.priv.enter", 123))
        with pytest.raises(TypeError), lm.PrivateLogCapture(CANARY, loggers=bad_names):
            pytest.fail("entered")
        assert (logger.level, list(logger.handlers), logger.propagate, logger.disabled) == before

    def test_the_canary_is_checked_when_the_record_is_emitted(self) -> None:
        handler = lm._BufferHandler(CANARY, max_records=1)
        handler.handle(logging.makeLogRecord({"msg": f"key {CANARY}", "levelno": 10}))
        handler.handle(logging.makeLogRecord({"msg": "innocent", "levelno": 10}))
        assert handler.leaked  # remembered although the bounded buffer has evicted the record
        assert CANARY not in "\n".join(handler.records)
        fragment = logging.makeLogRecord({"msg": f"part {CANARY[20:34]}", "levelno": 10})
        other = lm._BufferHandler(CANARY)
        other.handle(fragment)
        assert other.leaked

    def test_a_leak_in_a_log_record_is_a_leak_of_the_logs_stream_only(self) -> None:
        with lm.PrivateLogCapture(CANARY) as logs:
            logging.getLogger("claude_agent_sdk").debug("k %s", CANARY)
        assert logs.leaked
        streams = clean_streams()
        streams["logs"] = logs.text
        report = lm.scan_report(CANARY, streams, case="L1")
        assert report.leaks == ("logs",)

    def test_record_text_is_bounded(self) -> None:
        with lm.PrivateLogCapture(CANARY) as logs:
            logging.getLogger("claude_agent_sdk").debug("x" * 50_000)
        assert len(logs.text) <= 2000

    def test_a_record_that_cannot_be_formatted_never_raises_into_the_sdk(self) -> None:
        class Broken:
            def __str__(self) -> str:
                raise RuntimeError("no str")

        with lm.PrivateLogCapture(CANARY):
            logging.getLogger("claude_agent_sdk").debug("value %s", Broken())


class TestAuthorizedCommands:
    """H21 (vii): the commands the runbook shows and a maintainer may be authorized to run."""

    COMMANDS = {
        "readiness_probe_only": lm.READINESS_ONLY_COMMAND,
        "official_live_evidence": lm.OFFICIAL_COMMAND,
    }

    @staticmethod
    def tokens(command: str) -> list[str]:
        return shlex.split(command.replace("\\\n", " "))

    @pytest.mark.parametrize("selector", list(COMMANDS))
    def test_flags(self, selector: str) -> None:
        command = self.COMMANDS[selector]
        tokens = self.tokens(command)
        assert "-rA" not in tokens and "-s" not in tokens and "--capture=no" not in tokens
        assert "--show-capture=no" in tokens and "-q" in tokens and "--color=no" in tokens
        assert tokens.count("--disable-warnings") == 1 and "-W" not in tokens
        assert tokens.count("--tb=no") == 1 and tokens.count("-rN") == 1
        assert not [t for t in tokens if t.startswith("-r") and t != "-rN"]  # no other -r option
        assert tokens[tokens.index("-p") + 1] == "no:cacheprovider"
        assert tokens[tokens.index("real_api") - 1] == "-m"  # the marker gate (after `python -m`)
        assert tokens.count("-m") == 2 and tokens[tokens.index("-m") + 1] == "pytest"
        assert tokens[tokens.index("-k") + 1] == selector
        assert "export" not in tokens
        assert command.rstrip().endswith('2>&1 | tee "$EVIDENCE_FILE"')
        assert "$PWD/src" in command and '"$PY"' in command

    @pytest.mark.parametrize("selector", list(COMMANDS))
    def test_the_environment_prefix_and_assignments(self, selector: str) -> None:
        tokens = self.tokens(self.COMMANDS[selector])
        unset = [
            "PYTEST_ADDOPTS",
            "PYTEST_PLUGINS",
            "PYTEST_DEBUG",
            "PYTHONWARNINGS",
            "PYTHONDEVMODE",
            "PYTHONVERBOSE",
            "PYTHONPROFILEIMPORTTIME",
        ]
        assert tokens[0] == "env"
        # all seven unset operations, in this order, before the assignments and the interpreter
        assert tokens[1 : 1 + 2 * len(unset)] == [x for name in unset for x in ("-u", name)]
        rest = tokens[1 + 2 * len(unset) :]
        assert rest[:3] == [
            f"{lm.GATE_ENV}=1",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONPATH=$PWD/src",
        ]
        assert rest[3] == "$PY" and rest[4:6] == ["-m", "pytest"]
        assignments = [t for t in tokens if re.fullmatch(r"[A-Z_]+=.*", t)]
        assert len(assignments) == 3  # no other environment assignment
        assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD" not in " ".join(tokens)

    def test_the_two_commands_differ_only_in_the_selector(self) -> None:
        one = lm.READINESS_ONLY_COMMAND.replace("readiness_probe_only", "SEL")
        two = lm.OFFICIAL_COMMAND.replace("official_live_evidence", "SEL")
        assert one == two

    def test_the_selectors_name_the_two_live_tests(self) -> None:
        assert {f"test_{name}" for name in self.COMMANDS} == {
            n for n in dir(lm) if n.startswith("test_")
        }

    def test_pipefail_is_stated_for_the_pipe(self) -> None:
        assert lm.PIPEFAIL_LINE == "set -o pipefail"


class TestStructuralTripwires:
    """H24: any test that builds or calls a real adapter arms the tripwires before it does."""

    CALLEES = frozenset(
        {
            "RealReadinessAdapter",
            "RealWorkflowAdapter",
            "RealObserverInstaller",
            "RealDescendantAdapter",
            "RealCliEvidenceAdapter",
            "configured_adapters",
            "create_provider",
            "ProviderRegistry",
            "WorkflowEngine",
        }
    )
    EXPECTED = {
        "test_configured_adapters_construction_failure_is_adapters_not_wired",
        "test_configured_adapters_requires_the_gates",
        "test_configured_adapters_rejects_a_malformed_canary",
        "test_configured_adapters_returns_the_five_real_adapters",
        "test_constructing_the_adapter_set_enters_no_boundary_and_records_nothing",
        "test_each_real_adapter_refuses_to_run_without_the_gates",
    }

    @classmethod
    def structural_tests(cls, source: str) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
        tree = ast.parse(source)
        found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        candidates: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                candidates.append(node)
            elif isinstance(node, ast.ClassDef):
                candidates.extend(
                    m for m in node.body if isinstance(m, ast.FunctionDef | ast.AsyncFunctionDef)
                )
        for fn in candidates:
            if not fn.name.startswith("test_"):
                continue
            for call in ast.walk(fn):
                if isinstance(call, ast.Call):
                    target = call.func
                    name = (
                        target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
                    )
                    if name in cls.CALLEES:
                        found[fn.name] = fn
        return found

    @staticmethod
    def problems(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        params = {a.arg for a in fn.args.args}
        problems: list[str] = []
        if not {"boundary_hits", "stack"} & params:
            problems.append("the tripwire fixture is not requested")
        asserted = [
            ast.unparse(n.test)
            for n in ast.walk(fn)
            if isinstance(n, ast.Assert)
            and isinstance(n.test, ast.Compare)
            and ast.unparse(n.test.comparators[0]) == "[]"
        ]
        if not any(t in ("boundary_hits == []", "stack.hits == []") for t in asserted):
            problems.append("zero hits is not asserted")
        return problems

    def test_every_test_that_builds_a_real_adapter_arms_the_tripwires(self) -> None:
        found = self.structural_tests(Path(__file__).read_text())
        assert set(found) >= self.EXPECTED, sorted(self.EXPECTED - set(found))
        offenders = {name: self.problems(fn) for name, fn in found.items() if self.problems(fn)}
        assert offenders == {}

    def test_the_checker_rejects_a_test_without_the_fixture_or_the_assertion(self) -> None:
        source = (
            "def test_a(tmp_path):\n    configured_adapters(1)\n\n"
            "def test_b(boundary_hits):\n    lm.RealCliEvidenceAdapter(1)\n\n"
            "def test_c(boundary_hits):\n    ProviderRegistry(1)\n"
            "    assert boundary_hits == []\n\n"
            "class C:\n    def test_d(self, stack):\n        create_provider()\n"
            "        assert stack.hits == []\n"
            "def test_not_structural(tmp_path):\n    inspect.signature(create_provider)\n"
        )
        found = self.structural_tests(source)
        assert set(found) == {"test_a", "test_b", "test_c", "test_d"}
        assert self.problems(found["test_a"]) and self.problems(found["test_b"])
        assert not self.problems(found["test_c"]) and not self.problems(found["test_d"])

    def test_the_tripwire_fixture_arms_every_boundary(self) -> None:
        tree = ast.parse(Path(__file__).read_text())
        fixture = module_level_functions(tree)["boundary_hits"]
        armed = [
            ast.literal_eval(c.args[2])
            for c in ast.walk(fixture)
            if isinstance(c, ast.Call) and getattr(c.func, "id", "") == "arm"
        ]
        assert armed == [
            "Popen",
            "create_subprocess_exec",
            "create_subprocess_shell",
            "posix_spawn",
            "socket.connect",
            "create_connection",
            "anyio.open_process",
            "SubprocessCLITransport.connect",
        ]

    def test_the_tripwires_are_live_positive_control(self, boundary_hits: list[str]) -> None:
        for boundary in (
            lambda: subprocess.Popen(["true"]),
            lambda: os.posix_spawn("/bin/true", ["true"], {}),
        ):
            with pytest.raises(AssertionError, match="tripwire"):
                boundary()
        assert boundary_hits == ["Popen", "posix_spawn"]


# Planning-phase labels and "adapters are not wired" wording, built from parts so that this
# file does not match its own guard.
STALE_PATTERNS = (
    re.compile("Pha" + r"se\s+[AB]\b"),
    re.compile("fail closed until" + r".*" + "wired", re.IGNORECASE),
    re.compile(r"adapters?\s+(?:are\s+|remain\s+|stay\s+)?(?:un)?" + "wired", re.IGNORECASE),
    re.compile(r"\bun" + r"wired\b", re.IGNORECASE),
)


def comments_and_docstrings(source: str) -> list[str]:
    """Every comment and every docstring (never code or string data)."""
    texts = [
        tok.string
        for tok in tokenize.generate_tokens(io.StringIO(source).readline)
        if tok.type == tokenize.COMMENT
    ]
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                texts.append(doc)
    return texts


def stale_status(source: str) -> list[str]:
    return [
        f"{pattern.pattern}: {match.group(0)}"
        for text in comments_and_docstrings(source)
        for pattern in STALE_PATTERNS
        for match in [pattern.search(text)]
        if match
    ]


class TestStaleStatusGuard:
    """H26: no development-history label and no claim that adapters are missing."""

    @pytest.mark.parametrize("path", [LIVE_MODULE, Path(__file__)], ids=["live", "gate"])
    def test_no_stale_comment_or_docstring(self, path: Path) -> None:
        assert stale_status(path.read_text()) == []

    @pytest.mark.parametrize(
        "text",
        [
            "# " + "Pha" + "se A: offline",
            '"""Wired in ' + "Pha" + 'se B."""',
            "# fail closed until adapters are " + "wired",
            "# the adapters are " + "un" + "wired for now",
            "# " + "un" + "wired adapters fail closed",
        ],
    )
    def test_the_guard_detects_each_pattern(self, text: str) -> None:
        assert stale_status(f"{text}\nx = 1\n")

    def test_string_data_is_not_a_comment(self) -> None:
        assert stale_status('x = "' + "Pha" + 'se A"\n') == []


# ============================================================================
# Fabricated captures for the classifier tests (H40, H47, H48, H51)
# ============================================================================

CLEAN_SCAN = [f"{name}:clean" for name in lm.REQUIRED_STREAMS]
HEADING = "=" * 20 + " claude subscription live evidence " + "=" * 20
COUNT_OK = "1 passed, 1 deselected in 2.00s"
TRIO = (
    "!" * 30 + " KeyboardInterrupt " + "!" * 30,
    "interrupted: details withheld",
    "(to show a full traceback on KeyboardInterrupt use --full-trace)",
)


def rec(**fields: Any) -> str:
    return "EVIDENCE " + json.dumps(fields, sort_keys=True)


def session_fields(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "case": "session",
        "date_utc": "2026-10-01T00:00:00Z",
        "host_os": "Darwin",
        "python_version": "3.14.7",
        "sdk_version": "0.2.87",
        "git_sha": GIT_SHA,
        "git_dirty": False,
        "source_tree_verdict": "verified",
        "cli_class": "bundled",
        "cli_version": "2.1.150",
        "isolation_verdict": "isolated",
    }
    base.update(over)
    return base


def case_fields(case: str, outcome: str = "ok", **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "case": case,
        "outcome": outcome,
        "adapter_outcome": outcome,
        "secondary_findings": [],
        "interrupted": "none",
        "descendants": "no_descendants_remaining",
        "canary_scan": list(CLEAN_SCAN),
        "attempted_quota_execution": False,
    }
    base.update(over)
    return base


def run_fields(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "quota_attempts_total": 3,
        "quota_ceiling": 3,
        "pytest_version": "9.0.3",
        "plugins": ["anyio==4.12.1"],
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


OFFICIAL_OUTCOMES = (("L0", "ok"), ("L1", "ok"), ("L3", "invalid_key"), ("L2", "ok"))


def official_parts() -> dict[str, Any]:
    return {
        "session": session_fields(),
        "cases": [case_fields(c, o) for c, o in OFFICIAL_OUTCOMES],
        "run": run_fields(),
        "g4": (0, "pass", "true"),
        "count": COUNT_OK,
        "interrupt": False,
        "pre": ["." * 4 + " " * 60 + "[100%]"],
        "extra_section": [],
        "tail": [],
    }


def readiness_parts() -> dict[str, Any]:
    return {
        "session": None,
        "cases": [case_fields("L0", "ok")],
        "run": run_fields(quota_attempts_total=0),
        "g4": (0, "pass", "false"),
        "count": COUNT_OK,
        "interrupt": False,
        "pre": [".", ""],
        "extra_section": [],
        "tail": [],
    }


def build_capture(parts: Mapping[str, Any]) -> str:
    lines: list[str] = [*parts["pre"], HEADING]
    skipped, verdict, official = parts["g4"]
    lines += [
        f"skipped_reports: {skipped}",
        f"zero_skip_verdict: {verdict}",
        f"official: {official}",
    ]
    if parts["session"] is not None:
        lines.append(rec(**parts["session"]))
    lines += [rec(**c) for c in parts["cases"]]
    lines += list(parts["extra_section"])
    if parts["run"] is not None:
        lines.append(rec(**parts["run"]))
    if parts["interrupt"]:
        lines += list(TRIO)
    lines += list(parts["tail"])
    if parts["count"] is not None:
        lines.append(parts["count"])
    return "\n".join(lines) + "\n"


def classify(parts: Mapping[str, Any], status: int = 0) -> tuple[str, str]:
    return lm.classify_capture(build_capture(parts), status)


def edited(base: Callable[[], dict[str, Any]] | dict[str, Any], **changes: Any) -> dict[str, Any]:
    parts = dict(base() if callable(base) else base)
    parts.update(changes)
    return parts


def failing_readiness() -> dict[str, Any]:
    """A structurally valid readiness-only failure (status 1): the base of the grammar rows."""
    return edited(
        readiness_parts,
        cases=[case_fields("L0", "not_logged_in")],
        run=run_fields(quota_attempts_total=0, primary_failure="L0:not_logged_in:HarnessFailure"),
    )


# ============================================================================
# H40: classify_capture grammar and record checks
# ============================================================================


class TestClassifierGrammar:
    """H40: pure-text tests of the one function; the status is 1 unless a row says otherwise."""

    def test_the_valid_shapes_are_not_discarded(self) -> None:
        failing = edited(
            readiness_parts,
            cases=[case_fields("L0", "not_logged_in")],
            run=run_fields(
                quota_attempts_total=0, primary_failure="L0:not_logged_in:HarnessFailure"
            ),
        )
        assert classify(failing, 1) == ("failure_record", "ok")
        interrupted = edited(
            readiness_parts,
            cases=[case_fields("L0", "interrupted", interrupted="keyboard_interrupt")],
            run=run_fields(
                quota_attempts_total=0, primary_failure="L0:interrupted:KeyboardInterrupt"
            ),
            interrupt=True,
            count="no tests ran in 0.14s",
        )
        assert classify(interrupted, 2) == ("failure_record", "ok")
        setup_error = edited(
            failing,
            pre=["E" + " " * 70 + "[100%]"],
            count="1 error in 0.02s",
        )
        assert classify(setup_error, 1) == ("failure_record", "ok")

    @pytest.mark.parametrize(
        ("name", "line", "code"),
        [
            ("traceback", "Traceback (most recent call last):", "line_outside_grammar"),
            ("source", "    raise RuntimeError('x')", "line_outside_grammar"),
            ("rootdir", "rootdir: /Users/x/repo", "line_outside_grammar"),
            ("plugins", "plugins: anyio-4.12.1", "line_outside_grammar"),
            ("inifile", "inifile: pytest.ini", "line_outside_grammar"),
            ("stdout", "a line printed by an inherited -s", "line_outside_grammar"),
            ("plugin", "pytest-cov: some plugin banner", "line_outside_grammar"),
            ("path", "/Users/someone/.claude/x.py", "line_outside_grammar"),
            ("failed", "FAILED test_x.py::test_x - boom", "line_outside_grammar"),
            ("error", "ERROR test_x.py - boom", "line_outside_grammar"),
            ("failures", "=========== FAILURES ===========", "line_outside_grammar"),
            ("errors", "=========== ERRORS ===========", "line_outside_grammar"),
            ("summary", "=== short test summary info ===", "line_outside_grammar"),
            ("warnings", "=== warnings summary ===", "line_outside_grammar"),
            ("ansi", "\x1b[32m.\x1b[0m", "non_ascii_or_control"),
            ("tab", "a\tb", "non_ascii_or_control"),
            ("cr", "a\rb", "non_ascii_or_control"),
            ("nul", "a\x00b", "non_ascii_or_control"),
            ("non-ascii", "café", "non_ascii_or_control"),
            ("fourth", TRIO[1], "interrupt_grammar_violation"),
            (
                "hint",
                "(to show a full traceback on KeyboardInterrupt use --full-trace x)",
                "interrupt_grammar_violation",
            ),
        ],
    )
    def test_one_extra_line_of_each_kind_is_discarded(
        self, name: str, line: str, code: str
    ) -> None:
        parts = edited(readiness_parts, pre=[".", line])
        assert classify(parts, 1) == ("discard", code), name

    def test_interrupt_lines_must_be_exactly_the_three_in_place(self) -> None:
        base = edited(
            readiness_parts,
            cases=[case_fields("L0", "interrupted", interrupted="keyboard_interrupt")],
            run=run_fields(
                quota_attempts_total=0, primary_failure="L0:interrupted:KeyboardInterrupt"
            ),
            count="no tests ran in 0.14s",
        )
        good = edited(lambda: base, interrupt=True)
        assert classify(good, 2) == ("failure_record", "ok")
        code = ("discard", "interrupt_grammar_violation")
        assert classify(edited(lambda: good, tail=[TRIO[1]]), 2) == code  # a fourth line
        assert classify(edited(lambda: good, tail=[TRIO[2]]), 2) == code
        assert classify(edited(lambda: good, pre=[TRIO[0]]), 2) == code  # before the heading
        reordered = build_capture(good).replace(
            "\n".join(TRIO), "\n".join((TRIO[1], TRIO[0], TRIO[2]))
        )
        assert lm.classify_capture(reordered, 2) == code
        after_banner = build_capture(good).replace(
            "\n".join(TRIO), "\n".join(TRIO) + "\n" + rec(**case_fields("L1"))
        )
        assert lm.classify_capture(after_banner, 2) == code  # an evidence line after the banner
        only_two = build_capture(good).replace("\n" + TRIO[2], "")
        assert lm.classify_capture(only_two, 2) == code
        window = (
            build_capture(good)
            .replace(TRIO[0], "!" * 20 + " KeyboardInterrupt: PLANTED message " + "!" * 20)
            .replace(TRIO[1], "/Users/x/y.py:3: KeyboardInterrupt")
        )
        assert lm.classify_capture(window, 2) == code  # the registration-window rendering

    def test_the_heading_alone_is_never_enough(self) -> None:
        assert lm.classify_capture(HEADING + "\n", 1) == ("discard", "section_order_violation")
        assert lm.classify_capture(HEADING + "\nA hand-written line\n", 1)[0] == "discard"
        valid = build_capture(readiness_parts())
        assert lm.classify_capture(valid, 0)[0] == "readiness_only"
        assert lm.classify_capture(valid + "one more line\n", 0) == (
            "discard",
            "line_outside_grammar",
        )
        altered = valid.replace('"outcome": "ok"', '"outcome": "okay"')
        assert lm.classify_capture(altered, 0) == ("discard", "evidence_record_invalid")

    @pytest.mark.parametrize(
        ("text", "code"),
        [
            ("", "capture_empty"),
            ("just text\n", "no_evidence_section"),
            ("Traceback\n  conftest failed /Users/x\n", "no_evidence_section"),
            (HEADING + "\n" + HEADING + "\n", "multiple_evidence_sections"),
        ],
    )
    def test_no_section_an_empty_capture_and_several_headings(self, text: str, code: str) -> None:
        assert lm.classify_capture(text, 1) == ("discard", code)

    def test_invalid_statuses_are_rejected_before_the_text(self) -> None:
        for bad in (-1, 256, 1000, "0", None, True, 1.0):
            verdict = lm.classify_capture("", cast("Any", bad))
            assert verdict == ("discard", "pipeline_status_invalid")

    @pytest.mark.parametrize(
        ("payload", "code"),
        [
            ("{not json}", "evidence_json_malformed"),
            ('{"outcome": "ok", "outcome": "ok"}', "evidence_json_malformed"),
            ('{"passed": NaN}', "evidence_json_malformed"),
            ('{"passed": Infinity}', "evidence_json_malformed"),
            ("{}", None),
            ('{"stdout": "x"}', "evidence_record_invalid"),
            ('{"outcome": "made_up"}', "evidence_record_invalid"),
            ('{"canary_scan": "x"}', "evidence_record_invalid"),
        ],
    )
    def test_evidence_lines_are_strict_json_against_the_allowlist(
        self, payload: str, code: str | None
    ) -> None:
        parts = edited(readiness_parts)
        text = build_capture(parts).replace(
            "official: false\n", "official: false\nEVIDENCE " + payload + "\n", 1
        )
        verdict, found = lm.classify_capture(text, 1)
        if code is None:  # a valid empty record: a run-level record with no keys -> duplicates
            assert (verdict, found) == ("discard", "run_record_duplicate")
        else:
            assert (verdict, found) == ("discard", code)

    def test_record_checks(self) -> None:
        def check(parts: dict[str, Any], status: int = 1) -> tuple[str, str]:
            return classify(parts, status)

        no_run = edited(readiness_parts, run=None)
        assert check(no_run) == ("discard", "run_record_missing")
        two_runs = build_capture(readiness_parts()).replace(
            "1 passed", rec(**run_fields()) + "\n1 passed"
        )
        assert lm.classify_capture(two_runs, 1) == ("discard", "run_record_duplicate")
        repeated = edited(readiness_parts, cases=[case_fields("L0"), case_fields("L0")])
        assert check(repeated) == ("discard", "evidence_inconsistent")
        # primary_failure with the official line; a session: prefix with a per-case record
        pf = run_fields(
            quota_attempts_total=0,
            primary_failure="session:source_tree_mismatch:HarnessFailure",
            not_executed="L0:not_executed_after_safety_failure",
        )
        assert check(edited(readiness_parts, run=pf)) == ("discard", "evidence_inconsistent")
        official_line = edited(
            readiness_parts,
            cases=[case_fields("L0", "case_failed")],
            run=run_fields(primary_failure="L0:case_failed:HarnessFailure"),
            g4=(0, "pass", "true"),
        )
        assert check(official_line) == ("discard", "evidence_inconsistent")
        # a case prefix with no record of that case
        orphan = edited(
            official_parts,
            cases=[case_fields("L0")],
            run=run_fields(
                primary_failure="L1:case_failed:HarnessFailure",
                not_executed="L1:not_executed_after_l0_failure,L3:not_executed_after_l0_failure,L2:not_executed_after_l0_failure",
            ),
            g4=(0, "pass", "false"),
        )
        assert check(orphan) == ("discard", "evidence_inconsistent")
        # not_executed out of case order or with a duplicate case is not even a valid value
        for bad in (
            "L1:not_executed_after_l0_failure,L0:not_executed_after_l0_failure",
            "L1:not_executed_after_l0_failure,L1:not_executed_after_l0_failure",
        ):
            parts = edited(
                official_parts,
                cases=[case_fields("L0", "case_failed")],
                run=run_fields(primary_failure="L0:case_failed:HarnessFailure", not_executed=bad),
                g4=(0, "pass", "false"),
            )
            assert check(parts) == ("discard", "evidence_record_invalid")
        # a completed case listed in not_executed
        listed = edited(
            official_parts,
            cases=[case_fields("L0"), case_fields("L1", "case_failed")],
            run=run_fields(
                primary_failure="L1:case_failed:HarnessFailure",
                not_executed="L0:not_executed_after_l0_failure,L3:not_executed_after_l1_failure,L2:not_executed_after_l1_failure",
            ),
            g4=(0, "pass", "false"),
        )
        assert check(listed) == ("discard", "evidence_inconsistent")

    @pytest.mark.parametrize(
        "line",
        [
            "no tests ran in 0.14s",
            "1 passed in 0.00s",
            "3 passed, 1 skipped, 2 warnings in 1.50s (0:00:01)",
            "1 error in 0.02s",
            "1 failed, 4 passed, 1 skipped, 1 xfailed, 1 xpassed, 1 warning, 2 errors in 0.03s",
        ],
    )
    def test_every_closed_count_form_is_accepted(self, line: str) -> None:
        assert classify(edited(failing_readiness, count=line), 1)[0] != "discard"

    @pytest.mark.parametrize(
        "line",
        [
            "tests ran fine in 0.14s",
            "-1 passed in 0.01s",
            "1 flaky in 0.01s",
            "1 passed",
            "1 passed in 0.01s extra",
            "1 passed, 1 failed in 0.01s",
        ],
    )
    def test_every_loosened_count_form_is_rejected(self, line: str) -> None:
        assert classify(edited(failing_readiness, count=line), 1) == (
            "discard",
            "line_outside_grammar",
        )

    def test_a_capture_with_no_count_line_is_discarded(self) -> None:
        assert classify(edited(readiness_parts, count=None), 1) == ("discard", "count_line_missing")

    def test_the_collection_interruption_form(self) -> None:
        for line in (
            "!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!",
            "!!! Interrupted: 2 errors during collection !!!",
            "Interrupted: 1 error during collection",
        ):
            parts = edited(readiness_parts, tail=[line], count="1 error in 0.02s")
            assert classify(parts, 2)[0] != "discard", line
        bad = edited(
            readiness_parts,
            tail=["Interrupted: 1 errors during collection"],
            count="1 error in 0.02s",
        )
        assert classify(bad, 2) == ("discard", "line_outside_grammar")

    def test_unreadable_captures_are_discarded_with_their_codes(self, tmp_path: Path) -> None:
        missing = lm._read_capture(str(tmp_path / "nope"))
        assert missing == (None, "capture_missing")
        assert lm._read_capture(str(tmp_path)) == (None, "capture_unreadable")  # a directory
        big = tmp_path / "big"
        big.write_bytes(b"x" * (lm.MAX_CAPTURE_BYTES + 1))
        assert lm._read_capture(str(big)) == (None, "capture_too_large")
        exact_limit = tmp_path / "limit"
        exact_limit.write_bytes(b"x" * lm.MAX_CAPTURE_BYTES)
        assert lm._read_capture(str(exact_limit))[1] == "ok"
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        assert lm._read_capture(str(empty)) == (None, "capture_empty")
        high = tmp_path / "high"
        high.write_bytes(b"caf\xc3\xa9\n")
        assert lm._read_capture(str(high)) == (None, "non_ascii_or_control")
        locked = tmp_path / "locked"
        locked.write_bytes(b"x")
        locked.chmod(0)
        try:
            if os.geteuid() != 0:
                assert lm._read_capture(str(locked)) == (None, "capture_unreadable")
        finally:
            locked.chmod(0o600)

    def test_the_removed_headings_are_not_in_the_grammar_constants(self) -> None:
        source = LIVE_MODULE.read_text()
        head = source[: source.index('if __name__ == "__main__":')]
        for forbidden in ("FAILURES", "short test summary", "FAILED ", "ERROR "):
            assert forbidden not in "".join(lm.GRAMMAR.values()), forbidden
        assert "FRAMEWORK" + "_LINE" not in head and "TRACEBACK" + "_LINE" not in head

    def test_every_discard_carries_a_closed_code_and_no_capture_text(self) -> None:
        secret = "PLANTED-capture-secret-4417"
        for text in (secret, HEADING + "\n" + secret, build_capture(readiness_parts()) + secret):
            verdict, code = lm.classify_capture(text, 1)
            assert verdict == "discard" and code in lm.REASON_CODES
            assert secret not in f"{verdict} {code}"
        assert len(lm.REASON_CODES) == 20 == len(set(lm.REASON_CODES))


# ============================================================================
# H47: the four outcomes and the three-record model
# ============================================================================


class TestFourOutcomes:
    """H47: official, readiness_only, failure_record and discard, one mutation per contract item."""

    def test_the_official_capture(self) -> None:
        assert classify(official_parts(), 0) == ("official", "ok")

    @pytest.mark.parametrize(
        ("name", "change", "status", "expected"),
        [
            ("status 1", {}, 1, ("discard", "pipeline_status_nonzero")),
            ("g4c false", {"g4": (0, "pass", "false")}, 0, ("discard", "evidence_inconsistent")),
            (
                "zero-skip fail",
                {"g4": (1, "fail", "true")},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "skipped 1 only",
                {"g4": (1, "pass", "true")},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            ("no session", {"session": None}, 0, ("discard", "evidence_inconsistent")),
            (
                "session missing a key",
                {"session": {k: v for k, v in session_fields().items() if k != "cli_version"}},
                0,
                ("discard", "evidence_record_invalid"),
            ),
            (
                "session extra key",
                {"session": session_fields(requested_model="claude-haiku-4-5")},
                0,
                ("discard", "evidence_record_invalid"),
            ),
            (
                "dirty tree",
                {"session": session_fields(git_dirty=True), "g4": (0, "pass", "false")},
                0,
                ("failure_record", "ok"),
            ),
            (
                "source tree",
                {"session": session_fields(source_tree_verdict="mismatch")},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "isolation",
                {"session": session_fields(isolation_verdict="not_isolated")},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "three cases",
                {"cases": [case_fields(c, o) for c, o in OFFICIAL_OUTCOMES[:3]]},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "wrong order",
                {
                    "cases": [
                        case_fields(c, o)
                        for c, o in (
                            OFFICIAL_OUTCOMES[1],
                            OFFICIAL_OUTCOMES[0],
                            *OFFICIAL_OUTCOMES[2:],
                        )
                    ]
                },
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "L3 fell back",
                {
                    "cases": [
                        case_fields(c, "fell_back_to_login" if c == "L3" else o)
                        for c, o in OFFICIAL_OUTCOMES
                    ]
                },
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "run primary failure",
                {"run": run_fields(primary_failure="L3:fell_back_to_login:none")},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "quota 4",
                {"run": run_fields(quota_attempts_total=4)},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            ("quota 3", {"run": run_fields(quota_attempts_total=3)}, 0, ("official", "ok")),
            ("quota 0", {"run": run_fields(quota_attempts_total=0)}, 0, ("official", "ok")),
            ("quota 2", {"run": run_fields(quota_attempts_total=2)}, 0, ("official", "ok")),
            (
                "quota -1",
                {"run": run_fields(quota_attempts_total=-1)},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "quota -3",
                {"run": run_fields(quota_attempts_total=-3)},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "no quota",
                {"run": run_fields(quota_attempts_total=None)},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "fallback marker",
                {"extra_section": ["evidence_fallback_failed: L1"]},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "count 2 passed",
                {"count": "2 passed in 2.00s"},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            ("count 1 passed", {"count": "1 passed in 2.00s"}, 0, ("official", "ok")),
            ("count warnings", {"count": "1 passed, 2 warnings in 2.00s"}, 0, ("official", "ok")),
            (
                "count all three",
                {"count": "1 passed, 1 deselected, 1 warning in 2.00s"},
                0,
                ("official", "ok"),
            ),
            (
                "count skipped",
                {"count": "1 passed, 1 skipped in 2.00s"},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "count failed",
                {"count": "1 failed in 2.00s"},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "count error",
                {"count": "1 passed, 1 error in 2.00s"},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "count xfailed",
                {"count": "1 passed, 1 xfailed in 2.00s"},
                0,
                ("discard", "evidence_inconsistent"),
            ),
            (
                "no tests ran",
                {"count": "no tests ran in 0.10s"},
                0,
                ("discard", "evidence_inconsistent"),
            ),
        ],
    )
    def test_each_official_contract_item(
        self, name: str, change: dict[str, Any], status: int, expected: tuple[str, str]
    ) -> None:
        assert classify(edited(official_parts, **change), status) == expected, name

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("outcome", "inconclusive"),
            ("secondary_findings", ["canary_leak"]),
            ("cleanup_failed", ["evidence"]),
            ("interrupted", "cancelled"),
            ("descendants", "descendant_leak"),
        ],
    )
    def test_each_unsafe_case_field_stops_official(self, field: str, value: Any) -> None:
        for index in range(4):
            parts = official_parts()
            parts["cases"][index][field] = value
            # ``official: true`` over records that break item 6: the contract does not hold
            assert classify(parts, 0) == ("discard", "evidence_inconsistent"), (field, index)
            parts["g4"] = (0, "pass", "false")  # and without the claim it is not official either
            assert classify(parts, 0)[0] in ("failure_record", "discard"), (field, index)

    def test_every_leaking_or_incomplete_canary_scan_stops_official(self) -> None:
        for position in range(8):
            parts = official_parts()
            scan = list(CLEAN_SCAN)
            scan[position] = scan[position].replace("clean", "leak")
            parts["cases"][1]["canary_scan"] = scan
            assert classify(parts, 0) == ("discard", "evidence_inconsistent"), position
            parts["g4"] = (0, "pass", "false")
            assert classify(parts, 0)[0] != "official"
        for broken in (CLEAN_SCAN[:-1], [*CLEAN_SCAN, "tmp_files:clean"], CLEAN_SCAN[::-1]):
            parts = official_parts()
            parts["cases"][1]["canary_scan"] = broken
            assert classify(parts, 0)[0] == "discard"  # invalid record
        illegal = list(CLEAN_SCAN)
        illegal[2] = "logs:not_available"  # not allowed for the logs stream
        parts = official_parts()
        parts["cases"][1]["canary_scan"] = illegal
        assert classify(parts, 0) == ("discard", "evidence_inconsistent")
        parts["g4"] = (0, "pass", "false")
        assert classify(parts, 0)[0] != "official"

    def test_the_readiness_only_capture(self) -> None:
        assert classify(readiness_parts(), 0) == ("readiness_only", "ok")
        assert classify(readiness_parts(), 1) == ("discard", "pipeline_status_nonzero")
        # a readiness-only capture is never official: it can never carry ``official: true``
        assert classify(edited(readiness_parts, g4=(0, "pass", "true")), 0)[0] == "discard"
        with_session = edited(readiness_parts, session=session_fields())
        assert classify(with_session, 0)[0] != "readiness_only"
        for parts in (
            edited(readiness_parts, cases=[case_fields("L0", "not_logged_in")]),
            edited(readiness_parts, cases=[case_fields("L0"), case_fields("L1")]),
            edited(readiness_parts, cases=[case_fields("L0", secondary_findings=["canary_leak"])]),
            edited(
                readiness_parts,
                cases=[case_fields("L0", canary_scan=[*CLEAN_SCAN[:-1], "tmp_files:leak"])],
            ),
            edited(readiness_parts, count="2 passed in 0.10s"),
            edited(readiness_parts, count="1 passed, 1 skipped in 0.10s"),
        ):
            assert classify(parts, 0)[0] != "readiness_only"
        assert (
            classify(edited(readiness_parts, count="1 passed in 0.10s"), 0)[0] == "readiness_only"
        )
        assert classify(edited(readiness_parts, count="1 passed, 2 warnings in 0.10s"), 0) == (
            "readiness_only",
            "ok",
        )

    def test_failure_records(self) -> None:
        preflight = edited(
            readiness_parts,
            cases=[],
            run=run_fields(
                quota_attempts_total=0,
                primary_failure="session:prereq_cli_missing:HarnessFailure",
                not_executed="L0:not_executed_after_safety_failure",
            ),
            count="1 failed in 0.10s",
        )
        assert classify(preflight, 1) == ("failure_record", "ok")
        fell_back = edited(
            official_parts,
            cases=[
                case_fields("L0"),
                case_fields("L1"),
                case_fields("L3", "fell_back_to_login"),
            ],
            run=run_fields(
                quota_attempts_total=2,
                primary_failure="L3:fell_back_to_login:none",
                not_executed="L2:not_executed_l3_fell_back_to_login",
            ),
            g4=(0, "pass", "false"),
            count="1 failed in 5.00s",
        )
        assert classify(fell_back, 1) == ("failure_record", "ok")
        not_paired = edited(
            fell_back,
            cases=[
                case_fields("L0"),
                case_fields("L1"),
                case_fields("L3", "l2_l3_not_paired", attempted_quota_execution=False),
            ],
            run=run_fields(
                quota_attempts_total=1,
                primary_failure="L3:l2_l3_not_paired:HarnessFailure",
                not_executed="L2:not_executed_after_safety_failure",
            ),
        )
        assert classify(not_paired, 1) == ("failure_record", "ok")
        readiness_failure = edited(
            readiness_parts,
            cases=[case_fields("L0", "not_logged_in")],
            run=run_fields(
                quota_attempts_total=0, primary_failure="L0:not_logged_in:HarnessFailure"
            ),
            count="1 failed in 0.50s",
        )
        assert classify(readiness_failure, 1) == ("failure_record", "ok")
        dirty = edited(
            official_parts,
            session=session_fields(git_dirty=True),
            g4=(0, "pass", "false"),
        )
        assert classify(dirty, 0) == ("failure_record", "ok")  # a successful run on a dirty tree
        # a recorded failure with status 0 is contradictory
        assert classify(readiness_failure, 0) == ("discard", "evidence_inconsistent")

    def test_every_reason_code_is_producible(self) -> None:
        produced = {
            lm.classify_capture("", 1)[1],
            lm.classify_capture("x\x1b\n", 1)[1],
            lm.classify_capture("x\n", 1)[1],
            lm.classify_capture(HEADING + "\n" + HEADING + "\n", 1)[1],
            lm.classify_capture(HEADING + "\n", 1)[1],
            lm.classify_capture(HEADING + "\nxy\n", 1)[1],
            lm.classify_capture(
                build_capture(readiness_parts()).replace(
                    "1 passed", "!" * 5 + " KeyboardInterrupt: x " + "!" * 5
                ),
                1,
            )[1],
            lm.classify_capture(build_capture(edited(readiness_parts, run=None)), 1)[1],
            lm.classify_capture(build_capture(edited(readiness_parts, count=None)), 1)[1],
            lm.classify_capture("x", 999)[1],
            lm.classify_capture(build_capture(readiness_parts()), 1)[1],
            lm._read_capture("/nonexistent/capture")[1],
            lm._read_capture("/")[1],
            *(
                lm._classify_arguments(["m", *args])[1]
                for args in (
                    [],
                    ["--bogus"],
                    ["--check-capture", "f", "--pipeline-status", "999"],
                )
            ),
        }
        produced |= {
            "capture_too_large",
            "evidence_json_malformed",
            "evidence_record_invalid",
            "run_record_duplicate",
            "evidence_inconsistent",
            "internal_error",
        }  # each of these is produced by a dedicated test of this class or of H40
        assert set(lm.REASON_CODES) <= produced

    @pytest.mark.parametrize(
        ("session", "cases", "primary", "listed", "ok"),
        [
            # shape P
            (False, [], "session:isolation_fixtures_missing:HarnessFailure", "L0", True),
            (False, [], "session:isolation_fixtures_missing:HarnessFailure", "L0,L1,L3,L2", True),
            (False, [], "session:isolation_fixtures_missing:HarnessFailure", "L1", False),
            (False, ["L0"], "session:isolation_fixtures_missing:HarnessFailure", "L0", False),
            (True, ["L0"], "session:isolation_fixtures_missing:HarnessFailure", "L1,L3,L2", False),
            # a session-only enum with a case prefix; a case-level enum with the session prefix
            (True, ["L0"], "L0:adapters_not_wired:HarnessFailure", "L1,L3,L2", False),
            (False, [], "session:not_logged_in:HarnessFailure", "L0", False),
            (False, [], "session:l2_l3_not_paired:HarnessFailure", "L0", False),
            (False, [], "session:prereq_terminalreporter_missing:HarnessFailure", "L0", False),
            (True, ["L0"], "L0:prereq_terminalreporter_missing:HarnessFailure", "L1,L3,L2", False),
            (True, ["L0", "L1"], "L1:l2_l3_not_paired:HarnessFailure", "L3,L2", False),
            (True, ["L0", "L1", "L3"], "L3:l2_l3_not_paired:HarnessFailure", "L2", True),
            (True, ["L0", "L1", "L3"], "L3:interrupted:KeyboardInterrupt", "L2", True),
            # an ``ok`` outcome is never a primary failure, whichever case it names
            (True, ["L0", "L1", "L3"], "L3:ok:none", "L2", False),
            (True, ["L0"], "L0:ok:none", "L1,L3,L2", False),
            (True, ["L0", "L1"], "L0:ok:none", "L3,L2", False),
        ],
    )
    def test_the_record_model_shapes(
        self, session: bool, cases: list[str], primary: str, listed: str, ok: bool
    ) -> None:
        records = [case_fields(c, "ok") for c in cases]
        outcome = primary.split(":")[1]
        if cases and not primary.startswith("session"):
            prefix = primary.split(":")[0]
            for r in records:
                if r["case"] == prefix:
                    r["outcome"] = r["adapter_outcome"] = outcome
        not_executed = ",".join(f"{c}:not_executed_after_safety_failure" for c in listed.split(","))
        parts = edited(
            official_parts,
            session=session_fields() if session else None,
            cases=records,
            run=run_fields(primary_failure=primary, not_executed=not_executed),
            g4=(0, "pass", "false"),
            count="1 failed in 1.00s",
        )
        verdict = classify(parts, 1)
        assert (verdict == ("failure_record", "ok")) is ok, (primary, verdict)
        if not ok:  # the exact code: a shape violation, never an incidental internal error
            assert verdict == ("discard", "evidence_inconsistent"), (primary, verdict)

    def test_a_primary_failure_whose_enum_is_ok_is_rejected(self) -> None:
        """A completed ``ok`` case is never the primary failure: official-looking records plus a
        ``primary_failure`` naming ``ok`` are inconsistent, not a failure record."""
        for primary in ("L1:ok:none", "L0:ok:none", "L3:ok:HarnessFailure"):
            parts = official_parts()
            parts["g4"] = (0, "pass", "false")
            parts["run"] = run_fields(primary_failure=primary)
            assert classify(parts, 1) == ("discard", "evidence_inconsistent"), primary
            assert classify(parts, 0) == ("discard", "evidence_inconsistent"), primary
        readiness = readiness_parts()
        readiness["g4"] = (0, "pass", "false")
        readiness["run"] = run_fields(primary_failure="L0:ok:none")
        assert classify(readiness, 1) == ("discard", "evidence_inconsistent")

    def test_a_recorded_failure_over_official_looking_records_is_a_failure_record(self) -> None:
        """``primary_failure`` is an official-contract item of its own: with a shape-valid
        non-``ok`` primary failure the run is a failure record, never a records-say-official
        contradiction."""
        parts = official_parts()
        parts["g4"] = (0, "pass", "false")
        parts["run"] = run_fields(primary_failure="L3:invalid_key:HarnessFailure")
        assert classify(parts, 1) == ("failure_record", "ok")
        assert classify(parts, 0) == ("discard", "evidence_inconsistent")  # status 0 contradicts
        parts["g4"] = (0, "pass", "true")
        assert classify(parts, 1) == ("discard", "evidence_inconsistent")

    def test_a_pipeline_failure_marker_only_for_claimed_success(self) -> None:
        # a failure record with a nonzero status stays a failure_record; success claims fail
        assert classify(official_parts(), 3) == ("discard", "pipeline_status_nonzero")
        assert classify(readiness_parts(), 255) == ("discard", "pipeline_status_nonzero")

    def test_the_g4_lines_and_the_records_are_cross_checked(self) -> None:
        records_say_official = edited(official_parts, g4=(0, "pass", "false"))
        assert classify(records_say_official, 0) == ("discard", "evidence_inconsistent")
        mismatch = edited(official_parts, g4=(2, "pass", "false"))
        assert classify(mismatch, 1) == ("discard", "evidence_inconsistent")

    def test_the_allowlist_has_no_official_key_and_the_emitter_writes_g4_lines_only(self) -> None:
        assert not {"official", "skipped_reports", "zero_skip_verdict"} & lm.EVIDENCE_KEYS
        plugin = lm.ZeroSkipPlugin()
        lines: list[str] = []
        reporter = SimpleNamespace(
            section=lambda title: lines.append(title),
            write_line=lines.append,
        )
        plugin.pytest_terminal_summary(reporter, 0, None)
        assert lines[0] == "claude subscription live evidence"
        assert lines[1:4] == ["skipped_reports: 0", "zero_skip_verdict: pass", "official: false"]
        assert not any(line.startswith("EVIDENCE ") for line in lines)

    def test_a_status_argument_outside_the_range_is_invalid_before_the_capture_is_read(
        self, tmp_path: Path
    ) -> None:
        for value in ("256", "-1", "x", "", "1000"):
            args = [
                "m",
                "--check-capture",
                str(tmp_path / "never-read"),
                "--pipeline-status",
                value,
            ]
            assert lm._classify_arguments(args) == ("discard", "pipeline_status_invalid")


# ============================================================================
# H51: literal grammar tables
# ============================================================================

_DUR_T = r"[0-9]{1,6}\.[0-9]{2}s(?: \([0-9]{1,3}:[0-9]{2}:[0-9]{2}\))?"
_PCT_T = r"\[ {0,2}[0-9]{1,3}%\]"
_CNT_T = r"[0-9]{1,9} (?:failed|passed|skipped|deselected|xfailed|xpassed|warnings?|errors?)"
_OUT_T = r"[a-z][a-z0-9_]{0,63}"
_CLS_T = r"[A-Za-z_][A-Za-z0-9_]{0,63}"
_CASE_T = r"L0|L1|L3|L2"
_LIST_T = rf"(?:{_CASE_T}):{_OUT_T}(?:,(?:{_CASE_T}):{_OUT_T}){{0,7}}"
# The design's table with one accepted deviation (the advisory of the acceptance review): the
# ``first_failure:`` prefix of G9d may also be the fixed ``session``.
EXPECTED_GRAMMAR = {
    "G2": rf"[.sFExX]{{1,512}}(?: {{1,512}}{_PCT_T})?",
    "G3": r"={1,200} claude subscription live evidence ={1,200}",
    "G4a": r"skipped_reports: [0-9]{1,9}",
    "G4b": r"zero_skip_verdict: (?:pass|fail)",
    "G4c": r"official: (?:true|false)",
    "G5": r"EVIDENCE \{[\x20-\x7e]{0,16000}\}",
    "G6": r"evidence_fallback_failed: (?:L0|L1|L3|L2)",
    "G7a": r"!{1,200} KeyboardInterrupt !{1,200}",
    "G7b": r"interrupted: details withheld",
    "G7c": r"\(to show a full traceback on KeyboardInterrupt use --full-trace\)",
    "G8a": rf"no tests ran in {_DUR_T}",
    "G8b": rf"{_CNT_T}(?:, {_CNT_T}){{0,7}} in {_DUR_T}",
    "G8c": r"(?:!{1,200} )?Interrupted: [0-9]{1,9} errors? during collection(?: !{1,200})?",
    "G9a": rf"unexpected exception(?:: {_CLS_T})?",
    "G9b": r"harness failure",
    "G9c": rf"{_OUT_T}:(?:HarnessFailure|LiveOptInError)",
    "G9d": (
        rf"cases: {_LIST_T}; first_failure: (?:{_CASE_T}|session|none):{_OUT_T}:"
        rf"(?:{_CLS_T}|none)(?:; also: {_LIST_T})?"
    ),
}

POSITIVE_LINES = [
    ("G1", ""),
    *(("G2", "." * 3 + mark) for mark in (".", "s", "F", "E", "x", "X")),
    ("G2", "." + " " * 70 + "[100%]"),
    ("G2", "." + " " * 70 + "[ 50%]"),
    ("G2", "." + " " * 70 + "[  5%]"),
    ("G3", "=" * 10 + " claude subscription live evidence " + "=" * 10),
    ("G4a", "skipped_reports: 0"),
    ("G4b", "zero_skip_verdict: pass"),
    ("G4b", "zero_skip_verdict: fail"),
    ("G4c", "official: true"),
    ("G4c", "official: false"),
    ("G5", 'EVIDENCE {"outcome": "ok"}'),
    *(("G6", f"evidence_fallback_failed: {c}") for c in ("L0", "L1", "L3", "L2")),
    ("G7a", TRIO[0]),
    ("G7b", TRIO[1]),
    ("G7c", TRIO[2]),
    ("G8a", "no tests ran in 0.14s"),
    ("G8b", "1 passed in 0.00s"),
    ("G8b", "1 passed, 1 deselected in 2.00s"),
    ("G8b", "3 passed, 1 skipped, 2 warnings in 1.50s (0:00:01)"),
    ("G8b", "1 failed, 91 passed, 1 skipped, 1 xfailed, 1 xpassed, 1 warning in 0.03s"),
    ("G8b", "1 error in 0.02s"),
    ("G8c", "!!! Interrupted: 1 error during collection !!!"),
    ("G8c", "Interrupted: 1 error during collection"),
    ("G8c", "!!!!!! Interrupted: 2 errors during collection !!!!!!"),
    ("G9a", "unexpected exception"),
    ("G9a", "unexpected exception: OSError"),
    ("G9b", "harness failure"),
    ("G9c", "case_failed:HarnessFailure"),
    ("G9c", "live_opt_in_error:LiveOptInError"),
    (
        "G9d",
        "cases: L0:ok,L1:case_failed; first_failure: L1:case_failed:HarnessFailure; "
        "also: L1:descendant_leak",
    ),
    (
        "G9d",
        "cases: L0:not_executed_after_safety_failure; "
        "first_failure: session:prereq_cli_missing:HarnessFailure",
    ),
    ("G9d", "cases: L0:ok,L1:ok,L3:fell_back_to_login; first_failure: L3:fell_back_to_login:none"),
]
NEGATIVE_LINES = [
    "=========== FAILURES ===========",
    "=========== ERRORS ===========",
    "=== short test summary info ===",
    "FAILED t.py::t - boom",
    "ERROR t.py",
    "rootdir: /x",
    "plugins: a-1",
    "inifile: x",
    "=== warnings summary ===",
    "t.py::test_a",
    "/Users/x/y.py",
    "\x1b[31mF\x1b[0m",
    "a\tb",
    "a\rb",
    "a\x00b",
    "café",
    "some free text",
    ".* anything",
]
# (maximum accepted, maximum plus one rejected), checked with the form's regex only
BOUNDARY = [
    ("G8b", "999999999 passed in 0.01s", "1000000000 passed in 0.01s"),
    ("G8b", "1 passed in 999999.99s", "1 passed in 1000000.00s"),
    ("G8b", "1 passed in 0.99s", "1 passed in 0.9s"),
    ("G8b", "1 passed in 0.99s", "1 passed in 0.999s"),
    ("G8b", "1 passed in 1.00s (999:59:59)", "1 passed in 1.00s (1000:00:00)"),
    ("G8b", "1 passed in 1.00s (0:05:00)", "1 passed in 1.00s (0:5:00)"),
    ("G2", "." + " " * 20 + "[100%]", "." + " " * 20 + "[1000%]"),
    ("G2", "." + " " * 20 + "[  5%]", "." + " " * 20 + "[   5%]"),
    ("G2", "." + " " * 20 + "[100%]", "." + " " * 20 + "[100 %]"),
    ("G2", "." * 512, "." * 513),
    ("G2", "." + " " * 512 + "[100%]", "." + " " * 513 + "[100%]"),
    (
        "G3",
        "=" * 200 + " claude subscription live evidence " + "=" * 200,
        "=" * 201 + " claude subscription live evidence " + "=",
    ),
    ("G7a", "!" * 200 + " KeyboardInterrupt " + "!" * 200, "!" * 201 + " KeyboardInterrupt " + "!"),
    (
        "G8b",
        "1 failed, 1 passed, 1 skipped, 1 deselected, 1 xfailed, 1 xpassed, 1 warning, "
        "1 error in 0.01s",
        "1 failed, 1 passed, 1 skipped, 1 deselected, 1 xfailed, 1 xpassed, 1 warning, "
        "1 error, 1 error in 0.01s",
    ),
    ("G9a", "unexpected exception: " + "C" * 64, "unexpected exception: " + "C" * 65),
    ("G9c", "a" * 64 + ":HarnessFailure", "a" * 65 + ":HarnessFailure"),
    (
        "G9d",
        "cases: " + ",".join(["L0:ok"] * 8) + "; first_failure: none:ok:none",
        "cases: " + ",".join(["L0:ok"] * 9) + "; first_failure: none:ok:none",
    ),
    ("G5", "EVIDENCE {" + "x" * 16000 + "}", "EVIDENCE {" + "x" * 16001 + "}"),
    (
        "G8c",
        "Interrupted: 999999999 errors during collection",
        "Interrupted: 1000000000 errors during collection",
    ),
]
# rejected by the semantic checks that follow the regex (no zero, no leading zero, plurals, order)
SEMANTIC_NEGATIVES = [
    "0 passed in 0.01s",
    "01 passed in 0.01s",
    "1 warnings in 1.00s",
    "2 warning in 1.00s",
    "1 errors in 1.00s",
    "1 passed, 1 failed in 1.00s",
    "1 passed, 1 passed in 1.00s",
    "Interrupted: 2 error during collection",
    "Interrupted: 1 errors during collection",
]


class TestGrammarTables:
    """H51: pure text on the compiled grammar constants."""

    def test_the_literal_regex_text_equals_the_table(self) -> None:
        assert dict(lm.GRAMMAR) == EXPECTED_GRAMMAR

    @pytest.mark.parametrize(("form", "line"), POSITIVE_LINES)
    def test_every_form_has_a_positive_line(self, form: str, line: str) -> None:
        assert lm._form_of(line) == form, line

    @pytest.mark.parametrize("line", NEGATIVE_LINES)
    def test_every_exclusion_has_a_negative_line(self, line: str) -> None:
        assert lm._form_of(line) is None, line

    @pytest.mark.parametrize(("form", "ok", "bad"), BOUNDARY)
    def test_the_digit_boundary_table(self, form: str, ok: str, bad: str) -> None:
        pattern = lm._FORM_RES[form]
        assert pattern.fullmatch(ok) is not None, ok[:60]
        assert pattern.fullmatch(bad) is None, bad[:60]

    @pytest.mark.parametrize("line", SEMANTIC_NEGATIVES)
    def test_the_semantic_checks_reject_what_the_regex_lets_through(self, line: str) -> None:
        assert lm._form_of(line) is None, line

    def test_no_pattern_is_unbounded(self) -> None:
        for name, pattern in lm.GRAMMAR.items():
            assert ".*" not in pattern and "+" not in re.sub(r"\\\+|\[[^\]]*\]", "", pattern), name
            assert "{" in pattern or name in ("G4b", "G4c", "G6", "G7b", "G7c", "G9b"), name

    def test_the_precedence_of_g4_and_the_closed_set_of_forms(self) -> None:
        assert set(lm.GRAMMAR) | {"G1"} == {
            "G1",
            "G2",
            "G3",
            "G4a",
            "G4b",
            "G4c",
            "G5",
            "G6",
            "G7a",
            "G7b",
            "G7c",
            "G8a",
            "G8b",
            "G8c",
            "G9a",
            "G9b",
            "G9c",
            "G9d",
        }

    def test_progress_lines_at_realistic_widths_fit(self) -> None:
        for percent in ("[100%]", "[ 50%]", "[  5%]"):
            assert lm._form_of("." * 10 + " " * 60 + percent) == "G2"


# ============================================================================
# H50: static AST / order test of the classifier head
# ============================================================================

DISPATCH = 'if __name__ == "__main__":\n    sys.exit(classifier_main(sys.argv))\n'
HEAD_ALLOWED = ("re", "json", "sys", "enum", "typing", "collections.abc", "__future__")


def head_problems(source: str) -> list[str]:
    """Order and import problems of a module source whose classifier head must come first."""
    tree = ast.parse(source)
    body = tree.body
    problems: list[str] = []
    dispatch = next(
        (
            i
            for i, node in enumerate(body)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__"
        ),
        None,
    )
    if dispatch is None:
        return ["no dispatch statement"]
    exits = [n for n in ast.walk(body[dispatch]) if isinstance(n, ast.Call)]
    if not any(isinstance(c.func, ast.Attribute) and c.func.attr == "exit" for c in exits):
        problems.append("the dispatch does not exit")
    first = body[0]
    has_doc = isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
    index = 1 if has_doc else 0
    head_node = body[index]
    if not (isinstance(head_node, ast.ImportFrom) and head_node.module == "__future__"):
        problems.append("the head does not start with the future import")
    for node in body[:dispatch]:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Import):
                problems.extend(
                    f"head imports {a.name}" for a in sub.names if a.name not in HEAD_ALLOWED
                )
            elif isinstance(sub, ast.ImportFrom):
                if (sub.module or "") not in HEAD_ALLOWED:
                    problems.append(f"head imports from {sub.module}")
                if any(a.name == "*" for a in sub.names):
                    problems.append("star import in the head")
            elif isinstance(sub, ast.Call):
                func = sub.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                if name in ("__import__", "import_module", "exec", "eval"):
                    problems.append(f"head calls {name}")
    later = [
        sub
        for node in body[dispatch + 1 :]
        for sub in ast.walk(node)
        if isinstance(sub, ast.Import | ast.ImportFrom)
    ]
    if not later:
        problems.append("no ordinary import follows the dispatch")
    defined = {
        (n.name if isinstance(n, ast.FunctionDef | ast.ClassDef) else None) for n in body[:dispatch]
    }
    assigned = {
        t.id
        for n in body[:dispatch]
        if isinstance(n, ast.Assign | ast.AnnAssign)
        for t in ([n.target] if isinstance(n, ast.AnnAssign) else n.targets)
        if isinstance(t, ast.Name)
    }
    for name in ("classify_capture", "scan_is_clean_and_complete", "evidence", "Outcome"):
        if name not in defined:
            problems.append(f"{name} is not defined in the head")
    for name in ("GRAMMAR", "EVIDENCE_KEYS", "_EVIDENCE_SPECS"):
        if name not in assigned:
            problems.append(f"{name} is not defined in the head")
    return problems


class TestClassifierHeadStatic:
    """H50."""

    def test_the_real_module_has_the_pinned_head(self) -> None:
        assert head_problems(LIVE_MODULE.read_text()) == []

    def test_the_evidence_emitter_shares_the_heads_objects(self) -> None:
        source = LIVE_MODULE.read_text()
        tree = ast.parse(source)
        evidence_fn = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "evidence"
        )
        names = {n.id for n in ast.walk(evidence_fn) if isinstance(n, ast.Name)}
        assert "validate_record" in names  # the same validator the classifier applies
        assert lm.evidence is not None and lm.EVIDENCE_KEYS is lm.EVIDENCE_KEYS
        validate = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "validate_record"
        )
        assert "_EVIDENCE_SPECS" in {n.id for n in ast.walk(validate) if isinstance(n, ast.Name)}
        assert source.count("_EVIDENCE_SPECS: Final") == 1  # defined once

    @pytest.mark.parametrize(
        ("name", "change", "expected"),
        [
            (
                "subprocess before the dispatch",
                (
                    'if __name__ == "__main__":\n    sys.exit(classifier_main(sys.argv))\n',
                    "import subprocess\n" + DISPATCH,
                ),
                "head imports subprocess",
            ),
            (
                "nested import in a head function",
                ("def _discard(code: str)", "def _discard(code: str, _x=__import__('pytest'))"),
                "head calls __import__",
            ),
            (
                "pytest in a head function",
                (
                    "    return VERDICT_DISCARD, code\n",
                    "    import pytest\n    return VERDICT_DISCARD, code\n",
                ),
                "head imports pytest",
            ),
            (
                "dispatch below an ordinary import",
                (
                    'if __name__ == "__main__":\n    sys.exit(classifier_main(sys.argv))\n',
                    "import conductor\n" + DISPATCH,
                ),
                "head imports conductor",
            ),
            (
                "star import",
                ("from typing import Any, Final, cast", "from typing import *"),
                "star import",
            ),
        ],
    )
    def test_positive_controls_each_fail_the_check(
        self, name: str, change: tuple[str, str], expected: str
    ) -> None:
        source = LIVE_MODULE.read_text()
        old, new = change
        assert old in source, name
        mutated = source.replace(old, new, 1)
        assert any(expected in p for p in head_problems(mutated)), (name, head_problems(mutated))

    def test_the_dispatch_must_exit(self) -> None:
        source = LIVE_MODULE.read_text().replace(
            "sys.exit(classifier_main(sys.argv))", "classifier_main(sys.argv)", 1
        )
        assert "the dispatch does not exit" in head_problems(source)


# ============================================================================
# Class C: the classifier entry point (H42, H49)
# ============================================================================

FORBIDDEN_CLASSIFIER_MODULES = frozenset(
    {
        "pytest",
        "_pytest",
        "conductor",
        "claude_agent_sdk",
        "anyio",
        "asyncio",
        "subprocess",
        "socket",
        "selectors",
        "ssl",
        "http",
        "urllib",
        "threading",
        "logging",
        "site",
    }
)

DRIVER = r"""
import importlib.util
import io
import json
import os
import runpy
import sys
from contextlib import redirect_stdout

trip_path, module, capture, status, out_path = sys.argv[1:6]
spec = importlib.util.spec_from_file_location("tripwires", trip_path)
trip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trip)  # Layer 1, armed explicitly by file path
flags = {
    "isolated": sys.flags.isolated,
    "no_site": sys.flags.no_site,
    "dont_write_bytecode": bool(sys.dont_write_bytecode),
    "site_loaded": "site" in sys.modules,
}
snapshot = set(sys.modules)  # after the tripwire's own imports
sys.argv = [module, "--check-capture", capture, "--pipeline-status", status]
buffer = io.StringIO()
code = error = None
try:
    with redirect_stdout(buffer):
        runpy.run_path(module, run_name="__main__")
except SystemExit as exc:
    code = exc.code
except BaseException as exc:
    error = type(exc).__name__
hits = open(trip.HITS).read().split() if os.path.exists(trip.HITS) else []
result = {
    "stdout": buffer.getvalue(),
    "code": code,
    "error": error,
    "hits": hits,
    "flags": flags,
    "delta": sorted(set(sys.modules) - snapshot),
}
with open(out_path, "w") as handle:
    json.dump(result, handle)
"""


class ClassC:
    """Class C (design section 10): the real module run as a script; no pytest process."""

    def __init__(self, root: Path) -> None:
        self.root = root
        for sub in ("home", "tmp", "xdg-config", "xdg-data", "xdg-cache", "work"):
            (root / "_sbx" / sub).mkdir(parents=True, exist_ok=True)
        (root / "tripwires.py").write_text(LAYER1_PLUGIN)

    @property
    def work(self) -> Path:
        return self.root / "_sbx" / "work"

    def environment(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        base = self.root / "_sbx"
        env = {
            "HOME": str(base / "home"),
            "TMPDIR": str(base / "tmp"),
            "XDG_CONFIG_HOME": str(base / "xdg-config"),
            "XDG_DATA_HOME": str(base / "xdg-data"),
            "XDG_CACHE_HOME": str(base / "xdg-cache"),
            "PATH": SYSTEM_PATH,
        }
        assert not [k for k in env if k.startswith(("ANTHROPIC_", "CLAUDE_", "CONDUCTOR_"))]
        assert shutil.which("claude", path=SYSTEM_PATH) is None
        env.update(extra or {})  # a vector's own declared variables only
        return env

    def capture(self, text: str | bytes, name: str = "capture.txt") -> Path:
        path = self.work / name
        path.write_bytes(text if isinstance(text, bytes) else text.encode())
        return path

    def command(
        self,
        capture: str | Path,
        status: str | int,
        *,
        flags: Sequence[str] = lm.CLASSIFIER_FLAGS,
        module: Path = LIVE_MODULE,
        pass_status: bool = True,
        python: str | None = None,
    ) -> list[str]:
        argv = [python or sys.executable, *flags, str(module), "--check-capture", str(capture)]
        if pass_status:
            argv += ["--pipeline-status", str(status)]
        return argv

    def run(
        self, argv: Sequence[str], *, env: Mapping[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.before = self.tree()
        done = subprocess.run(
            list(argv),
            cwd=self.work,
            env=self.environment(env),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.after = self.tree()  # the classifier reads only: nothing is created or rewritten
        return done

    def tree(self) -> dict[str, bytes | None]:
        out: dict[str, bytes | None] = {}
        for path in sorted(self.root.rglob("*")):
            out[str(path.relative_to(self.root))] = path.read_bytes() if path.is_file() else None
        return out


@pytest.fixture
def class_c(tmp_path: Path) -> ClassC:
    return ClassC(tmp_path)


VALID = {
    "official": (build_capture(official_parts()), 0, "official", 0),
    "readiness_only": (build_capture(readiness_parts()), 0, "readiness_only", 0),
    "failure_record": (
        build_capture(
            edited(
                readiness_parts,
                cases=[case_fields("L0", "not_logged_in")],
                run=run_fields(
                    quota_attempts_total=0, primary_failure="L0:not_logged_in:HarnessFailure"
                ),
            )
        ),
        1,
        "failure_record",
        3,
    ),
}


class TestClassifierEntryPoint:
    """H42: Class C, the exact hardened invocation, the explicit driver and the import audit."""

    @pytest.mark.parametrize("name", list(VALID))
    def test_a_valid_capture_prints_its_verdict_and_status(
        self, class_c: ClassC, name: str
    ) -> None:
        text, status, token, exit_status = VALID[name]
        path = class_c.capture(text)
        done = class_c.run(class_c.command(path, status))
        assert (done.stdout, done.returncode, done.stderr) == (token + "\n", exit_status, "")
        assert class_c.before == class_c.after  # read-only: no deletion, rewrite or __pycache__
        again = class_c.run(class_c.command(path, status))
        assert (again.stdout, again.returncode) == (done.stdout, done.returncode)  # deterministic

    def test_every_reason_code_is_printed_with_status_one(self, class_c: ClassC) -> None:
        valid = build_capture(readiness_parts())
        cases: dict[str, tuple[Path | str, str | int, bool]] = {}

        def add(code: str, content: str | bytes | None, status: str | int = 1) -> None:
            path = class_c.work / "nope" if content is None else class_c.capture(content, code)
            cases[code] = (path, status, True)

        add("capture_missing", None)
        cases["capture_unreadable"] = (class_c.work, 1, True)  # a directory
        add("capture_too_large", b"x" * (lm.MAX_CAPTURE_BYTES + 1))
        add("capture_empty", b"")
        add("non_ascii_or_control", b"caf\xc3\xa9\n")
        add("no_evidence_section", "just a line\n")
        add("multiple_evidence_sections", HEADING + "\n" + HEADING + "\n")
        add("section_order_violation", HEADING + "\n")
        add("line_outside_grammar", HEADING + "\nrootdir: /Users/x\n")
        add("interrupt_grammar_violation", valid.replace("1 passed", TRIO[1] + "\n1 passed"))
        add(
            "evidence_json_malformed",
            valid.replace("official: false\n", "official: false\nEVIDENCE {bad}\n"),
        )
        add("evidence_record_invalid", valid.replace('"outcome": "ok"', '"outcome": "okay"'))
        add("run_record_missing", build_capture(edited(readiness_parts, run=None)))
        add("run_record_duplicate", valid.replace("1 passed", rec(**run_fields()) + "\n1 passed"))
        add(
            "evidence_inconsistent",
            build_capture(edited(readiness_parts, cases=[case_fields("L0"), case_fields("L0")])),
        )
        add("count_line_missing", build_capture(edited(readiness_parts, count=None)))
        add("pipeline_status_nonzero", valid, 1)
        cases["pipeline_status_nonzero"] = (class_c.capture(valid, "p"), 1, True)
        cases["pipeline_status_invalid"] = (class_c.capture(valid, "q"), "256", True)
        for code, (path, status, _) in cases.items():
            done = class_c.run(class_c.command(path, status))
            assert (done.stdout, done.returncode, done.stderr) == (f"discard {code}\n", 1, ""), code
        # the two argument errors of the entry point, and the internal error of a broken module
        base = class_c.command(class_c.capture(valid, "r"), 0)
        for argv, code in (
            ([sys.executable, *lm.CLASSIFIER_FLAGS, str(LIVE_MODULE)], "usage_error"),
            ([*base[:5], "--bogus"], "usage_error"),
            ([*base, "extra"], "usage_error"),
            (
                class_c.command(class_c.capture(valid, "s"), 0, pass_status=False),
                "pipeline_status_invalid",
            ),
            ([*base, "--pipeline-status", "1"], "pipeline_status_invalid"),  # a repeated option
            (class_c.command(class_c.capture(valid, "t"), ""), "pipeline_status_invalid"),
            (class_c.command(class_c.capture(valid, "u"), "-1"), "pipeline_status_invalid"),
            (class_c.command(class_c.capture(valid, "v"), "x1"), "pipeline_status_invalid"),
            (class_c.command(class_c.capture(valid, "w"), "1000"), "pipeline_status_invalid"),
        ):
            done = class_c.run(argv)
            assert (done.stdout, done.returncode, done.stderr) == (f"discard {code}\n", 1, ""), argv
        broken = class_c.root / "broken_module.py"
        broken.write_text(
            LIVE_MODULE.read_text().replace(
                "        return _classify(text, pipeline_status)",
                '        raise RuntimeError("PLANTED-internal-4417")',
                1,
            )
        )
        done = class_c.run(class_c.command(class_c.capture(valid, "x"), 0, module=broken))
        assert (done.stdout, done.returncode, done.stderr) == ("discard internal_error\n", 1, "")

    def test_nothing_of_the_capture_is_echoed_and_stderr_is_empty(self, class_c: ClassC) -> None:
        secrets = [
            "PLANTED-secret-4417",
            "/Users/planted/.claude/x.py",
            "RuntimeError: PLANTED-boom",
        ]
        for index, line in enumerate(secrets):
            text = build_capture(readiness_parts()) + line + "\n"
            done = class_c.run(class_c.command(class_c.capture(text, f"c{index}"), 0))
            assert done.stdout == "discard line_outside_grammar\n" and done.stderr == ""
            assert line not in done.stdout + done.stderr

    def test_no_gate_and_no_environment_is_needed(self, class_c: ClassC) -> None:
        env = class_c.environment()
        assert not [k for k in env if k.startswith(("CONDUCTOR_", "ANTHROPIC_", "CLAUDE_"))]
        text, status, token, _ = VALID["readiness_only"]
        done = class_c.run(class_c.command(class_c.capture(text), status))
        assert done.stdout == token + "\n"

    def test_header_only_and_hand_edited_captures_cannot_pass(self, class_c: ClassC) -> None:
        valid = build_capture(readiness_parts())
        for index, text in enumerate(
            (
                HEADING + "\n",
                HEADING + "\nan unvalidated line\n",
                valid + "one appended line\n",
                valid.replace('"outcome": "ok"', '"outcome": "ok", "extra": 1'),
                valid.replace("official: false", "official: true"),
            )
        ):
            done = class_c.run(class_c.command(class_c.capture(text, f"h{index}"), 0))
            assert done.stdout.startswith("discard "), (index, done.stdout)

    # -- (b) the explicit driver and (c) the import-time audit ---------------------------------

    def run_driver(
        self, class_c: ClassC, module: Path, capture: Path, status: int
    ) -> dict[str, Any]:
        out = class_c.root / "driver_result.json"
        out.unlink(missing_ok=True)
        hits = class_c.work / "tripwire_hits.txt"
        hits.unlink(missing_ok=True)
        argv = [
            sys.executable,
            *lm.CLASSIFIER_FLAGS,
            "-c",
            DRIVER,
            str(class_c.root / "tripwires.py"),
            str(module),
            str(capture),
            str(status),
            str(out),
        ]
        done = class_c.run(argv)
        assert done.returncode == 0, done.stderr
        return json.loads(out.read_text())

    def test_the_driver_proves_zero_hits_the_flags_and_the_import_delta(
        self, class_c: ClassC
    ) -> None:
        text, status, token, exit_status = VALID["official"]
        result = self.run_driver(class_c, LIVE_MODULE, class_c.capture(text), status)
        assert result["error"] is None
        assert result["stdout"] == token + "\n" and result["code"] == exit_status
        assert result["hits"] == []  # zero tripwire hits (the driver armed Layer 1 itself)
        assert result["flags"] == {
            "isolated": 1,
            "no_site": 1,
            "dont_write_bytecode": True,
            "site_loaded": False,
        }
        assert self.delta_problems(result) == []

    @staticmethod
    def delta_problems(result: Mapping[str, Any]) -> list[str]:
        """The delta audit: only standard-library modules, none of the forbidden names."""
        tops = {name.split(".")[0] for name in result["delta"]}
        problems = [f"not stdlib: {t}" for t in sorted(tops - set(sys.stdlib_module_names))]
        problems += [f"forbidden: {t}" for t in sorted(tops & FORBIDDEN_CLASSIFIER_MODULES)]
        return problems

    def imported(self, class_c: ClassC, module: Path, capture: Path) -> set[str]:
        argv = [
            sys.executable,
            *lm.CLASSIFIER_FLAGS,
            "-X",
            "importtime",
            str(module),
            "--check-capture",
            str(capture),
            "--pipeline-status",
            "0",
        ]
        done = class_c.run(argv)
        names: set[str] = set()
        for line in done.stderr.splitlines():
            match = re.fullmatch(r"import time:\s+\d+ \|\s+\d+ \|\s+(\S+)", line)
            if match:
                names.add(match.group(1).split(".")[0])
        return names

    def test_the_import_time_audit_sees_only_the_standard_library(self, class_c: ClassC) -> None:
        capture = class_c.capture(VALID["readiness_only"][0])
        names = self.imported(class_c, LIVE_MODULE, capture)
        assert names, "the control run must name the imported modules"
        assert names <= set(sys.stdlib_module_names), names - set(sys.stdlib_module_names)
        assert not names & FORBIDDEN_CLASSIFIER_MODULES

    def head_copy(self, class_c: ClassC, extra: str, name: str) -> Path:
        source = LIVE_MODULE.read_text()
        marker = 'if __name__ == "__main__":\n    sys.exit(classifier_main(sys.argv))\n'
        copy = class_c.root / name
        copy.write_text(source.replace(marker, extra + marker, 1))
        return copy

    def test_positive_controls_a_heavy_import_before_the_dispatch_is_caught(
        self, class_c: ClassC
    ) -> None:
        capture = class_c.capture(VALID["readiness_only"][0])
        heavy = self.head_copy(class_c, "import subprocess\n", "heavy.py")
        assert "subprocess" in self.imported(class_c, heavy, capture)  # (c) sees it
        assert any("subprocess" in p for p in head_problems(heavy.read_text()))  # H50 sees it
        # the driver's delta cannot see it (the tripwire already loaded subprocess): (c) and H50 do
        result = self.run_driver(class_c, heavy, capture, 0)
        assert "subprocess" not in {n.split(".")[0] for n in result["delta"]}
        with_pytest = self.head_copy(class_c, "import pytest\n", "withpytest.py")
        failed = self.run_driver(class_c, with_pytest, capture, 0)
        assert failed["error"] == "ModuleNotFoundError" or "pytest" in " ".join(failed["delta"])
        assert any("pytest" in p for p in head_problems(with_pytest.read_text()))
        # a forbidden standard-library module the tripwire did not already load IS in the delta
        network_copy = self.head_copy(class_c, "import urllib.request\n", "withurllib.py")
        loaded = self.run_driver(class_c, network_copy, capture, 0)
        assert "forbidden: urllib" in self.delta_problems(loaded)
        assert any("urllib" in p for p in head_problems(network_copy.read_text()))
        noisy = class_c.root / "noisy.py"
        noisy.write_text(
            LIVE_MODULE.read_text().replace(
                '    sys.stdout.write(line + "\\n")',
                '    sys.stdout.write("extra\\n" + line + "\\n")',
                1,
            )
        )
        done = class_c.run(class_c.command(capture, 0, module=noisy))
        assert done.stdout != "readiness_only\n"  # a copy that prints extra text fails (a)(iii)

    def test_no_check_depends_on_sitecustomize_or_pythonpath(self) -> None:
        source = inspect.getsource(TestClassifierEntryPoint) + DRIVER
        assert "sitecustomize" not in DRIVER and "PYTHONPATH" not in DRIVER
        assert "importlib.util.spec_from_file_location" in DRIVER
        assert "runpy.run_path" in DRIVER and 'run_name="__main__"' in DRIVER
        assert source.count("-c") >= 1


# ============================================================================
# H49: startup hardening of the classifier
# ============================================================================

POISON_PRINTS = "import sys\nsys.stdout.write('official\\n')\nsys.exit(0)\n"


class TestClassifierStartup:
    """H49: one startup vector per run; every control proves the vector is live."""

    EXPECTED = ("readiness_only\n", 0)

    def check(
        self,
        done: subprocess.CompletedProcess[str],
        class_c: ClassC,
        before: dict[str, bytes | None] | None = None,
    ) -> None:
        assert (done.stdout, done.returncode) == self.EXPECTED
        assert done.stderr == ""
        assert class_c.before == class_c.after

    @pytest.fixture
    def armed(self, class_c: ClassC) -> tuple[ClassC, Path, dict[str, bytes | None]]:
        capture = class_c.capture(build_capture(readiness_parts()))
        return class_c, capture, class_c.tree()

    def poison_dir(self, class_c: ClassC, **modules: str) -> Path:
        directory = class_c.root / "poison"
        directory.mkdir(exist_ok=True)
        for name, source in modules.items():
            (directory / f"{name}.py").write_text(source)
        return directory

    @pytest.mark.parametrize("module", ["json", "re"])
    def test_a_shadowing_standard_library_module_cannot_forge_a_verdict(
        self, armed: Any, module: str
    ) -> None:
        class_c, capture, before = armed
        directory = self.poison_dir(class_c, **{module: POISON_PRINTS})
        env = {"PYTHONPATH": str(directory)}
        done = class_c.run(class_c.command(capture, 0), env=env)
        self.check(done, class_c, before)
        # the control without ``-I`` shows the forged ``official`` with exit status 0
        control = class_c.run(class_c.command(capture, 0, flags=("-S", "-B")), env=env)
        assert control.stdout == "official\n" and control.returncode == 0

    def test_a_pythonpath_sitecustomize_cannot_print_or_exit(self, armed: Any) -> None:
        class_c, capture, before = armed
        for index, source in enumerate((POISON_PRINTS, "import sys\nsys.exit(0)\n")):
            directory = self.poison_dir(class_c, sitecustomize=source)
            env = {"PYTHONPATH": str(directory)}
            self.check(class_c.run(class_c.command(capture, 0), env=env), class_c, before)
            # each flag alone is enough: -I ignores PYTHONPATH, -S never imports sitecustomize
            for flags in (("-I", "-B"), ("-S", "-B")):
                alone = class_c.run(class_c.command(capture, 0, flags=flags), env=env)
                assert (alone.stdout, alone.returncode) == self.EXPECTED, (index, flags)
            # the control with both removed shows the effect (so the vector is live)
            plain = class_c.run(class_c.command(capture, 0, flags=("-B",)), env=env)
            assert (plain.stdout, plain.returncode) != self.EXPECTED, index

    @pytest.mark.parametrize(
        ("variable", "value"),
        [
            ("PYTHONVERBOSE", "1"),
            ("PYTHONPROFILEIMPORTTIME", "1"),
        ],
    )
    def test_noisy_variables_cannot_reach_stderr(
        self, armed: Any, variable: str, value: str
    ) -> None:
        class_c, capture, before = armed
        env = {variable: value}
        self.check(class_c.run(class_c.command(capture, 0), env=env), class_c, before)
        control = class_c.run(class_c.command(capture, 0, flags=("-S", "-B")), env=env)
        assert control.stderr != ""  # the vector is live without ``-I``

    def test_a_bad_pythonhome_cannot_prevent_a_verdict(self, armed: Any) -> None:
        class_c, capture, before = armed
        env = {"PYTHONHOME": str(class_c.root / "does-not-exist")}
        self.check(class_c.run(class_c.command(capture, 0), env=env), class_c, before)
        control = class_c.run(class_c.command(capture, 0, flags=("-B",)), env=env)
        assert control.stdout == "" and control.returncode != 0  # a startup failure, no verdict

    def test_startup_and_bytecode_variables_are_ignored(self, armed: Any) -> None:
        class_c, capture, before = armed
        startup = class_c.root / "startup.py"
        startup.write_text(POISON_PRINTS)
        env = {
            "PYTHONSTARTUP": str(startup),
            "PYTHONWARNINGS": "error",
            "PYTHONDEVMODE": "1",
            "PYTHONUSERBASE": str(class_c.root / "userbase"),
            "PYTHONPYCACHEPREFIX": str(class_c.root / "pycache"),
        }
        self.check(class_c.run(class_c.command(capture, 0), env=env), class_c, before)
        assert not (class_c.root / "pycache").exists()

    def test_the_script_directory_is_not_on_the_path(self, armed: Any) -> None:
        class_c, capture, before = armed
        copy_dir = class_c.root / "copy"
        copy_dir.mkdir()
        module = copy_dir / LIVE_MODULE.name
        module.write_text(LIVE_MODULE.read_text())
        for name in ("json", "re"):
            (copy_dir / f"{name}.py").write_text(POISON_PRINTS)
        done = class_c.run(class_c.command(capture, 0, module=module))
        self.check(done, class_c, before)
        # without ``-I`` the script directory comes first on ``sys.path`` and forges the verdict
        control = class_c.run(class_c.command(capture, 0, flags=("-S", "-B"), module=module))
        assert control.stdout == "official\n" and control.returncode == 0

    def test_a_scratch_interpreter_layout_cannot_run_a_pth_line_under_S(self, armed: Any) -> None:
        class_c, capture, before = armed
        base = Path(os.path.realpath(sys.executable))
        layout = class_c.root / "layout"
        (layout / "bin").mkdir(parents=True)
        interpreter = layout / "bin" / "python"
        interpreter.symlink_to(base)
        (layout / "pyvenv.cfg").write_text(
            f"home = {base.parent}\ninclude-system-site-packages = false\n"
        )
        version = f"python{sys.version_info.major}.{sys.version_info.minor}"
        site = layout / "lib" / version / "site-packages"
        site.mkdir(parents=True)
        (site / "poison.pth").write_text("import sys; sys.stdout.write('official\\n')\n")
        python = str(interpreter)
        done = class_c.run(class_c.command(capture, 0, python=python))
        self.check(done, class_c, before)
        # ``-I -B`` without ``-S`` runs the ``.pth`` line: the vector is live, so ``-S`` is what
        # closes it (the pinned interpreter's own sitecustomize shadows a scratch one, so only the
        # ``.pth`` line is load-bearing here)
        control = class_c.run(class_c.command(capture, 0, flags=("-I", "-B"), python=python))
        assert "official\n" in control.stdout
        without_s_and_i = class_c.run(class_c.command(capture, 0, flags=("-B",), python=python))
        assert "official\n" in without_s_and_i.stdout

    def test_the_command_constant_has_the_flags_in_order(self) -> None:
        assert lm.CLASSIFIER_FLAGS == ("-I", "-S", "-B")
        assert '"$PY" -I -S -B tests/' in lm.CLASSIFY_BLOCK
        assert lm.CLASSIFY_BLOCK.rstrip().endswith("CLASSIFY_STATUS=$?")
        assert "2>/dev/null" in lm.CLASSIFY_BLOCK


# ============================================================================
# H48: the operator shell gate, executed verbatim against stand-ins
# ============================================================================

SHELLS = [pytest.param(BASH, id="bash", marks=needs_bash)]
if ZSH is not None:
    SHELLS.append(pytest.param(ZSH, id="zsh"))

STANDIN_CLASSIFIER = """#!/bin/sh
printf 'NOISE-ON-STDERR-4417\\n' >&2
printf '%s\\n' "$@" > "$ARGV_LOG"
printf '%b' "$STANDIN_STDOUT"
exit "${STANDIN_STATUS:-0}"
"""


@dataclasses.dataclass
class Gate:
    returncode: int
    stdout: str
    stderr: str
    file_exists: bool
    file_bytes: bytes | None
    ran: bool
    argv: list[str]
    pipeline_status: str


class GateRunner:
    """Runs the module's own PRE_GATE, status line, CLASSIFY_BLOCK and MATRIX_BLOCK."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.cls = ClassC(root)
        self.evidence = root / "outside" / "evidence.txt"
        self.evidence.parent.mkdir(parents=True, exist_ok=True)
        self.ran = root / "pytest_ran"
        self.argv_log = root / "argv.log"
        self.standin = root / "standin.sh"
        self.standin.write_text(STANDIN_CLASSIFIER)
        self.standin.chmod(0o755)

    def run(
        self,
        shell: str | None,
        *,
        pytest_status: int = 0,
        unwritable_after_gate: bool = False,
        expected: str | None = "readiness_only",
        classifier_stdout: str = "readiness_only\n",
        classifier_status: int = 0,
        evidence: Path | None = None,
        env: Mapping[str, str] | None = None,
        python: str | None = None,
        status_line: str = lm.PIPELINE_STATUS_LINE,
        between: str = "",
        classify_block: str = lm.CLASSIFY_BLOCK,
        matrix_block: str = lm.MATRIX_BLOCK,
        pre_gate: str = lm.PRE_GATE,
        preset: Mapping[str, str] | None = None,
    ) -> Gate:
        target = evidence or self.evidence
        self.ran.unlink(missing_ok=True)
        self.argv_log.unlink(missing_ok=True)
        chmod = 'chmod 0444 "$EVIDENCE_FILE"\n' if unwritable_after_gate else ""
        script = (
            pre_gate
            + chmod
            + f'( : > "$RAN"; printf "line\\\\n"; exit {pytest_status} ) | tee "$EVIDENCE_FILE"\n'
            + between
            + status_line
            + '\nprintf "STATUS=%s\\\\n" "$PIPELINE_STATUS" >&2\n'
            + classify_block
            + matrix_block
        )
        environment = self.cls.environment(
            {
                "PY": python or str(self.standin),
                "EVIDENCE_FILE": str(target),
                "RAN": str(self.ran),
                "ARGV_LOG": str(self.argv_log),
                "STANDIN_STDOUT": classifier_stdout,
                "STANDIN_STATUS": str(classifier_status),
                **({"EXPECTED": expected} if expected is not None else {}),
                **(env or {}),
            }
        )
        for key, value in (preset or {}).items():
            environment[key] = value
        assert shell is not None
        done = subprocess.run(
            [shell, "-c", script],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        status = re.findall(r"STATUS=(\S*)", done.stderr)
        return Gate(
            done.returncode,
            done.stdout,
            done.stderr,
            target.exists() or target.is_symlink(),
            target.read_bytes() if target.is_file() else None,
            self.ran.exists(),
            self.argv_log.read_text().split() if self.argv_log.exists() else [],
            status[-1] if status else "",
        )


@pytest.fixture
def gate(tmp_path: Path) -> GateRunner:
    return GateRunner(tmp_path)


KEPT_OK = "kept"
KEPT_FAILURE = "failure"
DELETED = "deleted"

# (classifier status, classifier stdout, EXPECTED) -> outcome
MATRIX_ROWS = [
    (0, "readiness_only\n", "readiness_only", KEPT_OK),
    (0, "official\n", "official", KEPT_OK),
    (3, "failure_record\n", "readiness_only", KEPT_FAILURE),
    (3, "failure_record\n", "official", KEPT_FAILURE),
    (0, "official\n", "readiness_only", DELETED),  # the token of the other run kind
    (0, "readiness_only\n", "official", DELETED),
    (0, "", "readiness_only", DELETED),  # a startup failure that exited 0
    (0, "readiness_only extra\n", "readiness_only", DELETED),
    (0, "readiness_only\nreadiness_only\n", "readiness_only", DELETED),  # two lines
    (0, "unexpected\n", "official", DELETED),
    (1, "discard capture_empty\n", "official", DELETED),
    (1, "discard\n", "official", DELETED),  # not of the form ``discard <code>``
    (1, "not a discard\n", "official", DELETED),
    (1, "", "official", DELETED),  # the interpreter failed to start
    (2, "official\n", "official", DELETED),
    (3, "official\n", "official", DELETED),
    (0, "failure_record\n", "official", DELETED),
    (127, "", "official", DELETED),
    (255, "official\n", "official", DELETED),
    (4, "failure_record\n", "official", DELETED),
]


@needs_bash
class TestShellGate:
    """H48: the exact pre-gate, status line, classifier block and matrix, from the constants."""

    @pytest.mark.parametrize("shell", SHELLS)
    @pytest.mark.parametrize(
        ("pytest_status", "tee_unwritable", "expected_status"),
        [(0, False, "0"), (2, False, "2"), (130, False, "130"), (0, True, "1"), (2, True, "1")],
    )
    def test_pipeline_status_is_the_pipeline_status_not_pytests_own(
        self,
        gate: GateRunner,
        shell: str,
        pytest_status: int,
        tee_unwritable: bool,
        expected_status: str,
    ) -> None:
        done = gate.run(shell, pytest_status=pytest_status, unwritable_after_gate=tee_unwritable)
        assert done.pipeline_status == expected_status, done.stderr
        assert done.argv[-2:] == ["--pipeline-status", expected_status] if done.argv else True

    @pytest.mark.parametrize("shell", SHELLS)
    def test_another_command_before_the_assignment_loses_the_status(
        self, gate: GateRunner, shell: str
    ) -> None:
        done = gate.run(shell, pytest_status=2, between="true\n")
        assert (
            done.pipeline_status == "0"
        )  # a control: the status line must be the very next command

    @pytest.mark.parametrize("shell", SHELLS)
    @pytest.mark.parametrize(("status", "stdout", "expected", "outcome"), MATRIX_ROWS)
    def test_the_status_and_token_matrix(
        self, gate: GateRunner, shell: str, status: int, stdout: str, expected: str, outcome: str
    ) -> None:
        done = gate.run(
            shell, expected=expected, classifier_stdout=stdout, classifier_status=status
        )
        if outcome == DELETED:
            assert not done.file_exists and done.returncode == 1, (status, stdout)
            assert "capture deleted; stop" in done.stdout
            assert "classified:" not in done.stdout
        elif outcome == KEPT_OK:
            assert done.file_exists and done.returncode == 0
            assert f"classified: {expected}" in done.stdout
        else:
            # retained, yet never a success: the script exits with the classifier's status 3
            assert done.file_exists and done.returncode == 3
            assert (
                "authorizes nothing" in done.stdout and f"classified: {expected}" not in done.stdout
            )
        # both the exit status and the exact stdout token are tested: neither alone decides
        assert done.argv[:4] == ["-I", "-S", "-B", lm._TEST_MODULE]

    @pytest.mark.parametrize("shell", SHELLS)
    @pytest.mark.parametrize(("status", "stdout", "expected", "outcome"), MATRIX_ROWS)
    def test_no_outer_caller_can_mistake_a_retained_failure_record_for_success(
        self, gate: GateRunner, shell: str, status: int, stdout: str, expected: str, outcome: str
    ) -> None:
        """Only an expected-token candidate exits 0: a kept failure record exits 3, a discard 1."""
        done = gate.run(
            shell, expected=expected, classifier_stdout=stdout, classifier_status=status
        )
        assert (done.returncode == 0) is (outcome == KEPT_OK), (status, stdout, done.returncode)
        if outcome == KEPT_FAILURE:
            assert done.file_exists and done.returncode == 3
        if outcome == DELETED:
            assert not done.file_exists and done.returncode not in (0, 3)

    @pytest.mark.parametrize("shell", SHELLS)
    def test_the_classifier_receives_exactly_the_hardened_arguments(
        self, gate: GateRunner, shell: str
    ) -> None:
        done = gate.run(
            shell, pytest_status=2, classifier_stdout="failure_record\n", classifier_status=3
        )
        assert done.argv == [
            "-I",
            "-S",
            "-B",
            lm._TEST_MODULE,
            "--check-capture",
            str(gate.evidence),
            "--pipeline-status",
            "2",
        ]
        assert done.pipeline_status == "2"

    @pytest.mark.parametrize("shell", SHELLS)
    @pytest.mark.parametrize("kind", ["file", "empty", "dangling_symlink"])
    def test_a_stale_path_stops_before_pytest_and_stays_byte_identical(
        self, gate: GateRunner, shell: str, kind: str
    ) -> None:
        if kind == "file":
            gate.evidence.write_bytes(b"stale content\n")
        elif kind == "empty":
            gate.evidence.write_bytes(b"")
        else:
            gate.evidence.symlink_to(gate.root / "no-such-target")
        before = gate.evidence.read_bytes() if gate.evidence.is_file() else None
        done = gate.run(shell)
        assert done.returncode != 0 and not done.ran  # the pytest stand-in never ran
        assert done.argv == []
        after = gate.evidence.read_bytes() if gate.evidence.is_file() else None
        assert after == before and (gate.evidence.is_symlink() or kind != "dangling_symlink")

    @pytest.mark.parametrize("shell", SHELLS)
    @pytest.mark.parametrize("where", ["missing_directory", "read_only_directory"])
    def test_an_unwritable_target_stops_before_pytest(
        self, gate: GateRunner, shell: str, where: str
    ) -> None:
        directory = gate.root / "ro"
        if where == "read_only_directory":
            directory.mkdir()
            directory.chmod(0o555)
        target = directory / "e.txt"
        try:
            if os.geteuid() == 0 and where == "read_only_directory":
                pytest.skip("root can write anywhere")
            done = gate.run(shell, evidence=target)
        finally:
            if directory.exists():
                directory.chmod(0o755)
        assert done.returncode != 0 and not done.ran and not target.exists()

    @pytest.mark.parametrize("shell", SHELLS)
    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("CLAUDE_CODE_TEST", "1"),
            ("CLAUDE_EFFORT", "high"),
            ("ANTHROPIC_API_KEY", "PLANTED-key-4417"),
        ],
    )
    def test_a_claude_or_anthropic_variable_stops_the_sequence_without_printing_it(
        self, gate: GateRunner, shell: str, name: str, value: str
    ) -> None:
        done = gate.run(shell, env={name: value})
        assert done.returncode != 0 and not done.ran
        assert value not in done.stdout + done.stderr and name not in done.stdout + done.stderr
        clean = gate.run(shell)
        assert clean.ran and clean.returncode == 0  # the same sequence proceeds without it

    @pytest.mark.parametrize("shell", SHELLS)
    def test_a_bare_claudecode_variable_is_not_a_policy(self, gate: GateRunner, shell: str) -> None:
        done = gate.run(shell, env={"CLAUDECODE": "1"})
        assert done.ran and done.returncode == 0  # no new gate is invented for it

    @pytest.mark.parametrize("shell", SHELLS)
    @pytest.mark.parametrize("empty", [True, False])
    def test_an_unset_or_empty_expected_cannot_accept_empty_classifier_output(
        self, gate: GateRunner, shell: str, empty: bool
    ) -> None:
        done = gate.run(
            shell, expected="" if empty else None, classifier_stdout="", classifier_status=0
        )
        assert done.returncode != 0 and not done.ran  # the pre-gate stops before any live action
        # and the matrix alone, with the pre-gate bypassed, also refuses (``0:`` must never match)
        bare = gate.run(
            shell,
            expected="" if empty else None,
            classifier_stdout="",
            classifier_status=0,
            pre_gate='set -o pipefail\n: > "$EVIDENCE_FILE"\n',
        )
        assert "classified:" not in bare.stdout and bare.returncode != 0
        assert bare.file_exists  # it stopped at the guard: nothing authorized, nothing deleted

    @pytest.mark.parametrize("shell", SHELLS)
    def test_without_the_expected_guard_empty_output_would_be_accepted(
        self, gate: GateRunner, shell: str
    ) -> None:
        """Positive control: why the guard is load-bearing."""
        unguarded = lm.MATRIX_BLOCK.replace(': "${EXPECTED:?}"', ":")
        assert unguarded != lm.MATRIX_BLOCK
        done = gate.run(
            shell,
            expected="",
            classifier_stdout="",
            classifier_status=0,
            pre_gate='set -o pipefail\n: > "$EVIDENCE_FILE"\n',
            matrix_block=unguarded,
            preset={"EXPECTED": ""},
        )
        assert "classified:" in done.stdout and done.returncode == 0  # the unguarded block accepts

    @pytest.mark.parametrize("shell", SHELLS)
    @pytest.mark.parametrize(("stdout", "status"), [("", 1), ("", 0)])
    def test_a_classifier_that_fails_to_start_deletes_the_capture(
        self, gate: GateRunner, shell: str, stdout: str, status: int
    ) -> None:
        done = gate.run(shell, classifier_stdout=stdout, classifier_status=status)
        assert not done.file_exists and done.returncode == 1

    @pytest.mark.parametrize("shell", SHELLS)
    def test_the_classifiers_stderr_never_reaches_the_terminal_or_the_verdict(
        self, gate: GateRunner, shell: str
    ) -> None:
        done = gate.run(shell)
        assert "NOISE-ON-STDERR-4417" not in done.stdout + done.stderr  # ``2>/dev/null``
        assert "classified: readiness_only" in done.stdout

    @pytest.mark.parametrize("shell", SHELLS)
    def test_a_classifier_that_cannot_be_executed_deletes_the_capture(
        self, gate: GateRunner, shell: str
    ) -> None:
        done = gate.run(shell, python=str(gate.root / "missing-interpreter"))
        assert not done.file_exists and done.returncode == 1

    @pytest.mark.parametrize("shell", SHELLS)
    def test_pipefail_is_on_after_the_pre_gate(self, gate: GateRunner, shell: str) -> None:
        script = lm.PRE_GATE + "set -o | grep -E '^pipefail[[:space:]]+on'\n"
        done = subprocess.run(
            [shell, "-c", script],
            cwd=gate.root,
            env=gate.cls.environment(
                {"EVIDENCE_FILE": str(gate.root / "outside" / "p.txt"), "EXPECTED": "official"}
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 0 and "pipefail" in done.stdout

    def test_generic_posix_sh_is_documented_only(self) -> None:
        text = RUNBOOK_PATH.read_text()
        assert "Bash or Zsh" in text and "not** generic POSIX `sh`" in text
        assert "dash" in text

    # -- (g) the real classifier through the same block -------------------------------------

    @pytest.mark.parametrize("shell", SHELLS)
    def test_the_real_classifier_is_run_with_the_pipeline_status(
        self, gate: GateRunner, shell: str
    ) -> None:
        text = build_capture(official_parts())

        def run(**kwargs: Any) -> Gate:
            gate.evidence.unlink(missing_ok=True)
            return gate.run(shell, python=sys.executable, expected="official", **kwargs)

        pre = 'set -o pipefail\n: > "$EVIDENCE_FILE"\n'
        gate_status_zero = gate.root / "official.txt"
        gate_status_zero.write_text(text)
        script_block = lm.CLASSIFY_BLOCK.replace(
            "tests/test_integration/test_claude_agent_sdk_subscription_real.py", str(LIVE_MODULE)
        )

        def real(status_line: str, classify: str) -> Gate:
            gate.evidence.unlink(missing_ok=True)
            gate.evidence.write_text(text)
            return gate.run(
                shell,
                python=sys.executable,
                expected="official",
                pre_gate=pre,
                status_line=status_line,
                classify_block=classify,
                between='cp "$OFFICIAL_COPY" "$EVIDENCE_FILE"\n',
                env={"OFFICIAL_COPY": str(gate_status_zero)},
            )

        ok = real("PIPELINE_STATUS=0", script_block)
        assert ok.file_exists and ok.returncode == 0 and "classified: official" in ok.stdout
        nonzero = real("PIPELINE_STATUS=1", script_block)
        assert not nonzero.file_exists and nonzero.returncode == 1
        assert "discard pipeline_status_nonzero" in nonzero.stdout
        omitted = real(
            "PIPELINE_STATUS=0",
            script_block.replace('    --pipeline-status "$PIPELINE_STATUS" \\\n', ""),
        )
        assert not omitted.file_exists and "discard pipeline_status_invalid" in omitted.stdout
        garbled = real("PIPELINE_STATUS=0", script_block.replace('"$PIPELINE_STATUS"', "abc"))
        assert not garbled.file_exists and "discard pipeline_status_invalid" in garbled.stdout


# ============================================================================
# H35: collection and setup failure output matrix (Class S)
# ============================================================================

COLLECTION_SECRET = "PLANTED-collect-4417"


def collection_scenarios(root: Path) -> dict[str, tuple[str, int]]:
    """``name -> (test module body, expected exit status)``; each plants a secret and a path."""
    where = str(root / "test_surface.py")
    return {
        "module_level": (
            "pytestmark = pytest.mark.real_api\n"
            f'raise RuntimeError("{COLLECTION_SECRET}-mod {where}")\n'
            "def test_x():\n    pass\n",
            2,
        ),
        "syntax_error": (
            f"pytestmark = pytest.mark.real_api\nPLANTED_syntax_4417 = = 1  # {where}\n"
            "def test_x():\n    pass\n",
            2,
        ),
        "missing_import": (
            "pytestmark = pytest.mark.real_api\nimport planted_missing_module_4417\n"
            "def test_x():\n    pass\n",
            2,
        ),
        "parametrize_error": (
            "pytestmark = pytest.mark.real_api\n"
            '@pytest.mark.parametrize("planted_argument_4417", [1])\n'
            "def test_x():\n    pass\n",
            2,
        ),
        "generate_tests_error": (
            "pytestmark = pytest.mark.real_api\n"
            "def pytest_generate_tests(metafunc):\n"
            f'    raise RuntimeError("{COLLECTION_SECRET}-gen {where}")\n'
            "def test_x(planted_param_4417):\n    pass\n",
            2,
        ),
        "fixture_discovery": (
            "pytestmark = pytest.mark.real_api\n"
            "def test_x(planted_missing_fixture_4417):\n    pass\n",
            1,
        ),
    }


PLANTED_MARKERS = (
    COLLECTION_SECRET,
    "PLANTED_syntax_4417",
    "planted_missing_module_4417",
    "planted_argument_4417",
    "planted_param_4417",
    "planted_missing_fixture_4417",
)


def exposes(out: str, root: Path) -> bool:
    """True iff ``out`` shows a planted value, a path of the sandbox or a source line."""
    return bool(
        any(marker in out for marker in PLANTED_MARKERS)
        or str(root) in out
        or re.search(r"^(?:E {3}[A-Za-z_]|> {3}\S)", out, re.M)
    )


@needs_bash
class TestCollectionMatrix:
    """H35: collection and setup failures through the exact pipeline, with negative controls."""

    @pytest.fixture
    def run(self, exact_scratch: Exact) -> Callable[..., Ran]:
        def go(name: str, **kwargs: Any) -> Ran:
            body, _ = collection_scenarios(exact_scratch.sandbox.pytester.path)[name]
            exact_scratch.module(body)
            kwargs.setdefault("allow_empty", True)
            return exact_scratch.run("test_surface.py", **kwargs)

        return go

    @pytest.mark.parametrize("name", list(collection_scenarios(Path("/x"))))
    def test_only_fixed_framework_lines_remain(
        self, exact_scratch: Exact, run: Callable[..., Ran], name: str
    ) -> None:
        ran = run(name)
        _, status = collection_scenarios(exact_scratch.sandbox.pytester.path)[name]
        out = ran.saved
        assert ran.returncode == status, out  # nonzero through ``pipefail`` and ``tee``
        for marker in PLANTED_MARKERS:
            assert marker not in out, (marker, out)
        assert local_path_problems(out, exact_scratch.sandbox.pytester.path) == [], out
        assert not exposes(out, exact_scratch.sandbox.pytester.path), out
        for banned in (
            "Traceback",
            "FAILURES",
            "ERRORS",
            "short test summary",
            "ERROR ",
            "FAILED ",
        ):
            assert banned not in out, banned
        assert output_problems(out) == [], out  # fixed progress and count lines only
        if status == 2:
            assert re.search(r"Interrupted: 1 error during collection", out), out
        else:
            assert re.search(r"(?m)^E\s+\[100%\]$|^E +\[", out) or "E" in out.splitlines()[0]
            assert re.search(r"1 error in [0-9.]+s", out), out
        assert exact_scratch.sandbox.hits() == []

    @pytest.mark.parametrize("name", list(collection_scenarios(Path("/x"))))
    def test_without_pipefail_the_status_is_masked(
        self, run: Callable[..., Ran], name: str
    ) -> None:
        assert run(name, pipefail=False).returncode == 0  # a positive control for ``pipefail``

    @pytest.mark.parametrize("name", list(collection_scenarios(Path("/x"))))
    def test_control_a_without_tb_no_exposes_every_scenario(
        self, exact_scratch: Exact, run: Callable[..., Ran], name: str
    ) -> None:
        """Keeping ``-rN`` but dropping ``--tb=no``: the planted value shows for every scenario."""
        ran = run(name, replace={"--tb=no -rN": "-rN"})
        assert any(m in ran.saved for m in PLANTED_MARKERS), ran.saved
        root = str(exact_scratch.sandbox.pytester.path)
        if name not in ("parametrize_error", "fixture_discovery"):
            # recorded: these two show only the message, the other four also a path or source line
            assert root in ran.saved or re.search(r"^(?:E {3}[A-Za-z_]|> {3}\S)", ran.saved, re.M)
        assert ran.verdict[0] == "discard"

    @pytest.mark.parametrize("mode", ["-rfE", "-rA", ""])
    @pytest.mark.parametrize("name", ["module_level", "generate_tests_error"])
    def test_control_b_other_summary_modes_expose_the_message(
        self, run: Callable[..., Ran], name: str, mode: str
    ) -> None:
        """Replacing ``-rN``: pytest's own short summary prints the collection message."""
        ran = run(name, replace={"--tb=no -rN": f"--tb=no {mode}".rstrip()})
        assert COLLECTION_SECRET in ran.saved, (mode, ran.saved)
        assert ran.verdict[0] == "discard"

    @pytest.mark.parametrize("mode", ["-rfE", "-rA", ""])
    def test_control_b_for_the_other_scenarios_records_what_the_mode_shows(
        self, exact_scratch: Exact, run: Callable[..., Ran], mode: str
    ) -> None:
        """Where a mode does not expose a scenario's message, control (a) is its control."""
        for name in ("syntax_error", "missing_import", "parametrize_error", "fixture_discovery"):
            ran = run(name, replace={"--tb=no -rN": f"--tb=no {mode}".rstrip()})
            shown = any(m in ran.saved for m in PLANTED_MARKERS)
            assert ran.verdict[0] == "discard"  # a ``FAILED``/``ERROR`` summary line at least
            assert ("ERROR " in ran.saved or "FAILED " in ran.saved) or not shown, (name, mode)

    @pytest.mark.parametrize("name", list(collection_scenarios(Path("/x"))))
    def test_control_c_dropping_both_flags_shows_the_union_and_a_summary_line(
        self, run: Callable[..., Ran], name: str
    ) -> None:
        ran = run(name, replace={"--tb=no -rN": ""})
        assert any(m in ran.saved for m in PLANTED_MARKERS)
        assert (
            re.search(r"^(?:ERROR|FAILED) ", ran.saved, re.M) or "short test summary" in ran.saved
        )

    def test_the_commands_contain_rn_and_no_other_r_option(self) -> None:
        for command in (lm.READINESS_ONLY_COMMAND, lm.OFFICIAL_COMMAND):
            tokens = shlex.split(command.replace("\\\n", " "))
            assert tokens.count("-rN") == 1
            assert not [t for t in tokens if t.startswith("-r") and t != "-rN"]


# ============================================================================
# H36: pre-reporter failures are non-official (Class S)
# ============================================================================

FAILING_CONFTEST = 'raise RuntimeError("PLANTED-conftest-4417 /Users/planted/home")\n'
FAILING_PLUGIN = 'raise RuntimeError("PLANTED-plugin-4417 /Users/planted/home")\n'


@needs_bash
class TestPreReporterFailures:
    """H36: a failure before pytest has a terminal reporter leaves no evidence section."""

    SCRATCH_TEST = "pytestmark = pytest.mark.real_api\ndef test_x():\n    pass\n"

    def classified(self, class_c: ClassC, ran: Ran) -> tuple[tuple[str, str], str, int]:
        in_process = lm.classify_capture(ran.saved, max(ran.returncode, 1))
        path = class_c.capture(ran.saved or "", "pre.txt")
        done = class_c.run(class_c.command(path, max(ran.returncode, 1)))
        return in_process, done.stdout, done.returncode

    def test_a_conftest_import_failure(self, exact_scratch: Exact, tmp_path: Path) -> None:
        exact_scratch.module(self.SCRATCH_TEST)
        exact_scratch.sandbox.write("conftest.py", FAILING_CONFTEST)
        ran = exact_scratch.run("test_surface.py", allow_empty=True)
        assert ran.returncode != 0
        assert "claude subscription live evidence" not in ran.saved
        assert "official: true" not in ran.saved
        # the flags cannot suppress it: this documents the boundary, it does not assert absence.
        # The file must be deleted: it is never shared, committed, quoted or used to authorize.
        verdict, stdout, status = self.classified(ClassC(tmp_path), ran)
        assert verdict[0] == "discard" and verdict[1] in ("no_evidence_section", "capture_empty")
        assert stdout == f"discard {verdict[1]}\n" and status == 1

    def test_a_plugin_load_failure_through_pytest_plugins(
        self, exact_scratch: Exact, tmp_path: Path
    ) -> None:
        exact_scratch.module(self.SCRATCH_TEST)
        exact_scratch.sandbox.write("failing_plugin.py", FAILING_PLUGIN)
        # a control that omits ``-u PYTEST_PLUGINS`` (the exact command removes it)
        ran = exact_scratch.run(
            "test_surface.py",
            drop=["-u PYTEST_PLUGINS"],
            env={"PYTEST_PLUGINS": "failing_plugin"},
            allow_empty=True,
        )
        assert ran.returncode != 0 and "claude subscription live evidence" not in ran.saved
        verdict, stdout, status = self.classified(ClassC(tmp_path), ran)
        assert verdict[0] == "discard" and status == 1 and stdout.startswith("discard ")
        # and with the exact command the variable is unset: the module is never imported
        exact_ran = exact_scratch.run(
            "test_surface.py", env={"PYTEST_PLUGINS": "failing_plugin"}, allow_empty=True
        )
        assert "PLANTED-plugin-4417" not in exact_ran.saved and exact_ran.returncode == 0

    def test_a_dash_p_plugin_failure(self, exact_scratch: Exact, tmp_path: Path) -> None:
        exact_scratch.module(self.SCRATCH_TEST)
        exact_scratch.sandbox.write("failing_plugin.py", FAILING_PLUGIN)
        ran = exact_scratch.run("test_surface.py", plugins=["failing_plugin"], allow_empty=True)
        assert ran.returncode != 0 and "claude subscription live evidence" not in ran.saved
        verdict, stdout, status = self.classified(ClassC(tmp_path), ran)
        assert verdict[0] == "discard" and status == 1

    def test_an_empty_capture_is_discarded(self, class_c: ClassC) -> None:
        assert lm.classify_capture("", 1) == ("discard", "capture_empty")
        done = class_c.run(class_c.command(class_c.capture(b"", "empty.txt"), 1))
        assert done.stdout == "discard capture_empty\n" and done.returncode == 1

    def test_a_capture_with_the_section_is_classified_only_after_every_line_validates(
        self,
    ) -> None:
        valid = build_capture(readiness_parts())
        assert lm.classify_capture(valid, 0)[0] == "readiness_only"
        assert lm.classify_capture(valid + "PLANTED-conftest-4417 /Users/x\n", 0)[0] == "discard"

    def test_no_repository_path_is_added_and_the_scratch_files_import_nothing(
        self, exact_scratch: Exact
    ) -> None:
        exact_scratch.module(self.SCRATCH_TEST)
        exact_scratch.sandbox.write("failing_plugin.py", FAILING_PLUGIN)
        for path in exact_scratch.sandbox.pytester.path.rglob("*.py"):
            text = path.read_text()
            assert str(REPO_ROOT) not in text, path.name  # no repository path is added
            if path.name == "tripwires.py":  # the stdlib-only Layer 1: it only names what it audits
                assert "import conductor" not in text
                continue
            assert scratch_import_problems(text) == [], path.name


# ============================================================================
# H39 / H45: pipeline, inherited configuration, colour and entry-point vectors (Class S)
# ============================================================================

INHERIT_TEST = """
import os
import sys
import warnings

import pytest

pytestmark = pytest.mark.real_api


def test_inherit_token_4417():
    print("PLANTED-print-4417")
    sys.stderr.write("PLANTED-stderr-4417\\n")
    os.write(1, b"PLANTED-fd1-4417\\n")
    os.write(2, b"PLANTED-fd2-4417\\n")
    warnings.warn("PLANTED-warn-4417", UserWarning)


def test_other():
    pass
"""
EXTERNAL_PLUGIN = """
import sys

sys.stdout.write("EXT-IMPORT-MARKER-4417\\n")


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    terminalreporter.write_line("EXT-SUMMARY-MARKER-4417")
"""
STDERR_PLUGIN = """
import sys

sys.stderr.write("STDERR-MARKER-4417\\n")
"""


def readiness_replay(sandbox: Sandbox) -> None:
    sandbox.write("replay.py", REPLAY_PLUGIN)
    sandbox.write("replay_data.json", replay_data(readiness_parts()))


@needs_bash
class TestInheritedConfiguration:
    """H39: ``-q``, ``2>&1`` and the inherited pytest configuration, each with a control."""

    NODE = "test_surface.py::test_inherit_token_4417"

    @pytest.fixture
    def replay(self, exact_scratch: Exact) -> Exact:
        exact_scratch.module(INHERIT_TEST)
        readiness_replay(exact_scratch.sandbox)
        return exact_scratch

    def go(self, replay: Exact, **kwargs: Any) -> Ran:
        kwargs.setdefault("plugins", ["replay"])
        kwargs.setdefault("allow_warnings", True)
        return replay.run(self.NODE, **kwargs)

    def test_the_clean_run_classifies_readiness_only(self, replay: Exact) -> None:
        ran = self.go(replay)
        assert ran.returncode == 0 and ran.verdict == ("readiness_only", "ok"), ran.saved

    def test_an_inherited_dash_s_is_removed_by_the_unset(self, replay: Exact) -> None:
        env = {"PYTEST_ADDOPTS": "-s"}
        ran = self.go(replay, env=env)
        for planted in ("PLANTED-print-4417", "PLANTED-fd1-4417", "PLANTED-stderr-4417"):
            assert planted not in ran.saved
        assert ran.verdict == ("readiness_only", "ok")
        control = self.go(replay, env=env, drop=["-u PYTEST_ADDOPTS"])
        assert "PLANTED-print-4417" in control.saved and "PLANTED-fd1-4417" in control.saved
        assert control.verdict[0] == "discard"

    def test_flag_precedence_is_documented_not_the_unset(self, replay: Exact) -> None:
        """The command's own flags win over three inherited options.  This proves nothing about
        ``env -u``: the unset is deliberately removed, so only the flag precedence is observed."""
        env = {"PYTEST_ADDOPTS": "-rA --tb=long --show-capture=all"}
        ran = self.go(replay, env=env, drop=["-u PYTEST_ADDOPTS"])
        assert "PLANTED" not in ran.saved and "Traceback" not in ran.saved
        assert "short test summary" not in ran.saved
        assert ran.verdict == ("readiness_only", "ok")

    def test_an_inherited_plugin_is_removed_by_the_unset(self, replay: Exact) -> None:
        replay.sandbox.write("extplugin.py", EXTERNAL_PLUGIN)
        env = {"PYTEST_PLUGINS": "extplugin"}
        ran = self.go(replay, env=env)
        assert "EXT-IMPORT-MARKER-4417" not in ran.saved
        assert "EXT-SUMMARY-MARKER-4417" not in ran.saved
        assert ran.verdict == ("readiness_only", "ok")
        control = self.go(replay, env=env, drop=["-u PYTEST_PLUGINS"])
        assert (
            "EXT-IMPORT-MARKER-4417" in control.saved and "EXT-SUMMARY-MARKER-4417" in control.saved
        )
        assert control.verdict[0] == "discard"

    def test_q_removes_the_rootdir_and_plugins_header(self, replay: Exact) -> None:
        ran = self.go(replay)
        assert "rootdir:" not in ran.saved and "plugins:" not in ran.saved
        control = self.go(replay, drop=["-q"])
        assert "rootdir:" in control.saved  # always: an absolute sandbox path
        has_entry_points = bool(importlib.metadata.entry_points(group="pytest11"))
        assert ("plugins:" in control.saved) == has_entry_points or not has_entry_points
        if has_entry_points:
            assert "plugins:" in control.saved
        assert control.verdict[0] == "discard"

    def test_the_plugins_assertion_is_conditional_and_the_rootdir_assertion_is_not(self) -> None:
        """H39 (iii): ``plugins:`` only with a ``pytest11`` entry point, ``rootdir:`` always."""
        source = inspect.getsource(
            TestInheritedConfiguration.test_q_removes_the_rootdir_and_plugins_header
        )
        assert 'entry_points(group="pytest11")' in source
        lines = source.splitlines()
        rootdir = next(line for line in lines if '"rootdir:" in control.saved' in line)
        assert rootdir.startswith("        assert")  # at method level: unconditional
        plugins = [line for line in lines if '"plugins:" in control.saved' in line]
        assert plugins and all(
            line.startswith(("        assert", "            assert")) for line in plugins
        )
        assert any("if has_entry_points" in line for line in lines)

    def test_2_to_1_places_stderr_in_the_capture(self, replay: Exact) -> None:
        replay.sandbox.write("stderrplugin.py", STDERR_PLUGIN)
        ran = self.go(replay, plugins=["replay", "stderrplugin"])
        assert "STDERR-MARKER-4417" in ran.saved  # merged into the capture ...
        assert ran.verdict[0] == "discard"  # ... where the classifier rejects it
        control = self.go(replay, plugins=["replay", "stderrplugin"], drop=["2>&1"])
        assert "STDERR-MARKER-4417" not in control.saved  # it went to the terminal instead
        assert "STDERR-MARKER-4417" in control.stderr

    def test_every_run_is_hermetic(self, replay: Exact) -> None:
        self.go(replay)
        assert replay.sandbox.hits() == []
        audit = replay.sandbox.pytester.path / "modules_audit.txt"
        assert audit.read_text().split() == []


@needs_bash
class TestInheritedPythonColourAndEntryPoints:
    """H45: the five Python-level unsets, ``--color=no`` and an auto-loaded entry-point plugin."""

    NODE = "test_surface.py::test_inherit_token_4417"
    VECTORS = {
        "PYTEST_DEBUG": "1",
        "PYTHONWARNINGS": "default",
        "PYTHONDEVMODE": "1",
        "PYTHONVERBOSE": "1",
        "PYTHONPROFILEIMPORTTIME": "1",
    }

    @pytest.fixture
    def replay(self, exact_scratch: Exact) -> Exact:
        exact_scratch.module(INHERIT_TEST)
        readiness_replay(exact_scratch.sandbox)
        return exact_scratch

    def go(self, replay: Exact, **kwargs: Any) -> Ran:
        kwargs.setdefault("plugins", ["replay"])
        kwargs.setdefault("allow_warnings", True)
        return replay.run(self.NODE, **kwargs)

    @pytest.mark.parametrize("variable", list(VECTORS))
    def test_each_python_level_unset_is_load_bearing(self, replay: Exact, variable: str) -> None:
        env = {variable: self.VECTORS[variable]}
        ran = self.go(replay, env=env)
        assert ran.verdict == ("readiness_only", "ok"), ran.saved
        control = self.go(replay, env=env, drop=[f"-u {variable}"])
        assert control.verdict[0] == "discard", (variable, control.saved[:300])
        extra = [ln for ln in control.saved.splitlines() if lm._form_of(ln) is None]
        assert extra, f"the control must show extra lines: {variable}"
        if variable in ("PYTHONVERBOSE", "PYTEST_DEBUG"):
            assert any("/" in ln for ln in extra)  # an absolute path where the review saw one

    @pytest.mark.parametrize("variable", ["FORCE_COLOR", "PY_COLORS"])
    def test_color_no_wins_over_the_colour_variables(self, replay: Exact, variable: str) -> None:
        env = {variable: "1"}
        ran = self.go(replay, env=env)
        assert "\x1b" not in ran.saved and ran.verdict == ("readiness_only", "ok")
        control = self.go(replay, env=env, drop=["--color=no"])
        assert "\x1b" in control.saved
        assert control.verdict == ("discard", "non_ascii_or_control")

    def test_an_entry_point_plugin_is_autoloaded_and_its_output_is_discarded(
        self, replay: Exact, tmp_path: Path
    ) -> None:
        sandbox_root = replay.sandbox.pytester.path
        replay.sandbox.write("extplug_mod.py", EXTERNAL_PLUGIN)
        dist = sandbox_root / "extplug-1.0.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: extplug\nVersion: 1.0\n")
        (dist / "entry_points.txt").write_text("[pytest11]\nextplug = extplug_mod\n")
        ran = self.go(replay)
        assert "EXT-IMPORT-MARKER-4417" in ran.saved  # genuinely auto-loaded (autoload stays on)
        assert "EXT-SUMMARY-MARKER-4417" in ran.saved
        assert ran.verdict == ("discard", "line_outside_grammar")
        done = ClassC(tmp_path).run(
            ClassC(tmp_path).command(ClassC(tmp_path).capture(ran.saved), ran.returncode)
        )
        assert done.returncode == 1 and done.stdout == "discard line_outside_grammar\n"
        for command in (lm.READINESS_ONLY_COMMAND, lm.OFFICIAL_COMMAND):
            assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD" not in command


# ============================================================================
# Class R: the real gate fixture, evidence plugin and test bodies over complete fakes
# ============================================================================

# Executed inside the sandbox, after the prelude loaded the live module as ``lm``.  Every external
# seam is a fake; every scenario knob arrives as JSON in ``SANDBOX_FAKE_SCRIPT``.
FAKE_WORLD = """

import asyncio
import contextlib
import functools
import json
import os
import sys
from pathlib import Path

from conductor.billing import SUBSCRIPTION_LABEL
from conductor.exceptions import ProviderError

SCRIPT = json.loads(os.environ.get("SANDBOX_FAKE_SCRIPT", "{}"))
CLEAN = dict.fromkeys(lm.REQUIRED_STREAMS, "")
CALLS = []


def l0_fields():
    return {
        "auth_method_present": True,
        "api_provider_present": True,
        "api_provider_is_first_party": True,
        "subscription_type_present": True,
        "api_key_source_present": False,
        "billing_mode": "subscription",
        "billing_reason": "first_party_login",
        "first_party_constant": "validated",
    }


def ok_run(cost=0.001):
    return lm.RunObservation(
        events=[
            {
                "type": "agent_completed",
                "data": {"billing_mode": "subscription", "model": "claude-haiku-4-5-20251001"},
            }
        ],
        exception=None,
        streams=dict(CLEAN),
        total_cost_usd=cost,
        effective_model="claude-haiku-4-5-20251001",
        fields={},
        output={"answer": "A workflow is a sequence of steps."},
        usage={
            "total_input_tokens": 12,
            "total_output_tokens": 8,
            "total_cost_usd": cost,
            "billing": {"state": "subscription", "breakdown": {"subscription": 1}},
        },
        console_text="Total: $0.0010 (" + SUBSCRIPTION_LABEL + ")",
    )


class Readiness:
    async def probe(self):
        CALLS.append("readiness")
        ready = SCRIPT.get("L0") != "not_logged_in"
        return lm.ReadinessObservation(ready, l0_fields())


class Workflow:
    def __init__(self, observer):
        self.observer = observer

    async def execute(self, variant):
        case = variant.case.value
        CALLS.append("execute:" + case)
        mode = SCRIPT.get(case, "default")
        if mode == "keyboard_interrupt":
            raise KeyboardInterrupt("PLANTED-interrupt-4417")
        if mode == "cancelled":
            raise asyncio.CancelledError()
        if mode == "boom":
            raise RuntimeError("PLANTED-case-boom-4417")
        if case == "L3":
            if mode == "fell_back":
                return ok_run()
            status = 404 if mode == "model_unavailable" else 401
            error = None if mode == "model_unavailable" else "authentication_failed"
            self.observer.sink.append(lm.Observation("ResultMessage", error, status, True))
            return lm.RunObservation(
                events=[],
                exception=ProviderError("rejected", is_retryable=False),
                streams=dict(CLEAN),
            )
        return ok_run(cost=0 if mode == "unpriced" else 0.001)


class Cli:
    def resolve(self):
        return lm.CliEvidence("bundled", "2.1.150")


class Descendants:
    def snapshot(self):
        return {}


class Observer:
    def __init__(self):
        self.sink = []

    def observing(self):
        @contextlib.contextmanager
        def cm():
            self.sink = []
            yield self.sink

        return cm()


def fake_configured_adapters(pytestconfig, tmp_path, monkeypatch, capfd, *, canary):
    pathb = SCRIPT.get("pathb")
    if pathb == "live_opt_in_error":
        raise lm.LiveOptInError()
    if pathb:
        extra = {"leak": "PLANTED-extra-4417"} if SCRIPT.get("plant") else None
        detail = "PLANTED-detail-4417 /Users/planted" if SCRIPT.get("plant") else ""
        cls = lm.HarnessFailure
        if SCRIPT.get("weird"):
            cls = type("Err\\u00f8r", (lm.HarnessFailure,), {})
        try:
            raise RuntimeError("PLANTED-cause-4417")
        except RuntimeError as cause:
            raise cls(lm.Outcome(pathb), detail, extra=extra) from cause
    observer = Observer()
    return lm.AdapterSet(
        readiness=Readiness(),
        workflow=Workflow(observer),
        cli=Cli(),
        descendants=Descendants(),
        observer=observer,
        board=lm.FindingsBoard(canary),
    )


lm.configured_adapters = fake_configured_adapters


def _raise_pairing(outcome):
    def raiser(*args, **kwargs):
        raise lm.HarnessFailure(outcome, "pairing")

    return raiser


if SCRIPT.get("pair") == "L3":
    lm.assert_config_paired = _raise_pairing(lm.Outcome.L2_L3_NOT_PAIRED)
if SCRIPT.get("pair") == "L2":
    lm.assert_env_paired = _raise_pairing(lm.Outcome.L2_L3_NOT_PAIRED)
if SCRIPT.get("quota"):
    _Real = lm.QuotaCounter
    lm.QuotaCounter = lambda: _Real(ceiling=SCRIPT["quota"])
if SCRIPT.get("source_tree"):
    sys.modules["conductor"].__file__ = "/nonexistent/elsewhere/conductor/__init__.py"
if SCRIPT.get("not_bundled"):
    import conductor.providers.claude_agent_sdk as _sdk_module

    _sdk_module._find_claude_cli = lambda: Path("/usr/bin/true")
"""

OFFICIAL_NODE = "test_live.py::test_official_live_evidence"
READINESS_NODE = "test_live.py::test_readiness_probe_only"
ALL_CASES_NOT_EXECUTED = ",".join(f"{c}:not_executed_after_safety_failure" for c in lm.CASE_NAMES)


@dataclasses.dataclass
class RealRun:
    ran: Ran
    records: list[dict[str, Any]]

    @property
    def run_level(self) -> list[dict[str, Any]]:
        return [r for r in self.records if "case" not in r]

    @property
    def cases(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("case") in lm.CASE_NAMES]

    @property
    def session(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("case") == "session"]


def real_run(
    exact: Exact,
    node: str = OFFICIAL_NODE,
    *,
    script: Mapping[str, Any] | None = None,
    extra_conftest: str = "",
    exports: Sequence[str] = LIVE_EXPORTS,
    env: Mapping[str, str] | None = None,
    **kwargs: Any,
) -> RealRun:
    exact.module(
        FAKE_WORLD,
        extra_conftest=extra_conftest,
        exports=exports,
        filename="test_live.py",
    )
    environment = {"SANDBOX_FAKE_SCRIPT": json.dumps(script or {}), **(env or {})}
    ran = exact.run(node, env=environment, allow_warnings=True, **kwargs)
    return RealRun(ran, evidence_records(ran.saved))


@needs_bash
class TestRunLevelEvidence:
    """H38 (ii)-(iv), (vi): every enum of the pinned placement table, through real code."""

    PATH_B = [
        ("prereq_report_sanitizer_unavailable", "HarnessFailure"),
        ("live_opt_in_error", "LiveOptInError"),
        ("isolation_fixtures_missing", "HarnessFailure"),
        ("adapters_not_wired", "HarnessFailure"),
    ]

    @pytest.mark.parametrize(("enum", "cls"), PATH_B)
    @pytest.mark.parametrize(
        ("node", "selected"),
        [
            (OFFICIAL_NODE, ALL_CASES_NOT_EXECUTED),
            (READINESS_NODE, "L0:not_executed_after_safety_failure"),
        ],
    )
    def test_path_b_failures_leave_one_fixed_run_level_record(
        self, exact: Exact, enum: str, cls: str, node: str, selected: str
    ) -> None:
        if enum == "prereq_report_sanitizer_unavailable":
            out = real_run(exact, node, extra_conftest=DROP_MEMO_CONFTEST)
        else:
            out = real_run(exact, node, script={"pathb": enum})
        assert out.ran.returncode == 1
        assert len(out.records) == 1 and len(out.run_level) == 1  # exactly one run-level record
        record = out.run_level[0]
        assert record["primary_failure"] == f"session:{enum}:{cls}"
        assert record["not_executed"] == selected  # the case set comes from the collected items
        assert record["quota_attempts_total"] == 0
        assert out.ran.verdict == ("failure_record", "ok"), out.ran.saved
        assert "official: false" in out.ran.saved  # the G4 line; ``official`` is not a record key
        assert not {"official", "skipped_reports", "zero_skip_verdict"} & set(record)

    PATH_A = [
        ("prereq_file_console_active", {"extra_conftest": EXTRA_FILE_CONSOLE}, "HarnessFailure"),
        ("source_tree_mismatch", {"script": {"source_tree": True}}, "HarnessFailure"),
        ("readiness_stub_active", {"exports": LIVE_EXPORTS_NO_OVERRIDE}, "HarnessFailure"),
        ("prereq_cli_missing", {"extra_conftest": EXTRA_CLI_NONE}, "HarnessFailure"),
        ("prereq_cli_not_bundled", {"script": {"not_bundled": True}}, "HarnessFailure"),
        ("prereq_sdk_missing", {"extra_conftest": EXTRA_SDK_BLOCKED}, "HarnessFailure"),
        ("prereq_ps_missing", {"extra_conftest": EXTRA_PS_MISSING}, "HarnessFailure"),
        (
            "invalid_model_override",
            {"env": {lm.MODEL_ENV: "not a valid model!"}},
            "HarnessFailure",
        ),
        ("case_failed", {"env": {"SANDBOX_GIT_FAIL": "1"}}, "HarnessFailure"),
    ]

    @pytest.mark.parametrize(("enum", "kwargs", "cls"), PATH_A)
    def test_path_a_preflight_failures_leave_exactly_one_session_record(
        self, exact: Exact, enum: str, kwargs: dict[str, Any], cls: str
    ) -> None:
        pytest.importorskip("claude_agent_sdk")
        out = real_run(exact, OFFICIAL_NODE, **kwargs)
        assert out.ran.returncode == 1, out.ran.saved
        assert len(out.run_level) == 1 and out.cases == [] and out.session == []  # shape P
        record = out.run_level[0]
        assert record["primary_failure"] == f"session:{enum}:{cls}"
        assert record["not_executed"] == ALL_CASES_NOT_EXECUTED
        assert out.ran.verdict == ("failure_record", "ok"), out.ran.saved

    def test_a_readiness_only_preflight_failure_marks_l0_alone(self, exact: Exact) -> None:
        out = real_run(exact, READINESS_NODE, extra_conftest=EXTRA_CLI_NONE)
        (record,) = out.run_level
        assert record["primary_failure"] == "session:prereq_cli_missing:HarnessFailure"
        assert record["not_executed"] == "L0:not_executed_after_safety_failure"
        assert out.cases == [] and out.session == []

    @pytest.mark.parametrize(
        ("mode", "cls", "returncode"),
        [("keyboard_interrupt", "KeyboardInterrupt", 2), ("cancelled", "CancelledError", 1)],
    )
    def test_an_interrupt_after_completed_cases_leaves_them_intact(
        self, exact: Exact, mode: str, cls: str, returncode: int
    ) -> None:
        """Real fixture and case wrapper over fake adapters: L0, L1 ok, then L3 is interrupted."""
        pytest.importorskip("claude_agent_sdk")
        out = real_run(exact, OFFICIAL_NODE, script={"L3": mode})
        assert out.ran.returncode == returncode, out.ran.saved
        assert [(r["case"], r["outcome"]) for r in out.cases] == [
            ("L0", "ok"),
            ("L1", "ok"),
            ("L3", "interrupted"),
        ]
        assert len(out.session) == 1 and len(out.run_level) == 1
        run = out.run_level[0]
        assert run["primary_failure"] == f"L3:interrupted:{cls}"
        assert run["not_executed"] == "L2:not_executed_after_interrupt"
        assert run["quota_attempts_total"] == 2
        assert out.ran.verdict == ("failure_record", "ok"), out.ran.saved

    CASE_LEVEL = [
        (
            "not_logged_in",
            {"L0": "not_logged_in"},
            "L0:not_logged_in:HarnessFailure",
            "L1:not_executed_after_l0_failure,L3:not_executed_after_l0_failure,L2:not_executed_after_l0_failure",
            ["L0"],
            0,
        ),
        (
            "unpriced_model_label_unexercised",
            {"L1": "unpriced"},
            "L1:unpriced_model_label_unexercised:HarnessFailure",
            "L3:not_executed_after_l1_failure,L2:not_executed_after_l1_failure",
            ["L0", "L1"],
            1,
        ),
        (
            "model_unavailable",
            {"L3": "model_unavailable"},
            "L3:model_unavailable:ProviderError",
            "L2:not_executed_l3_model_unavailable",
            ["L0", "L1", "L3"],
            2,
        ),
        (
            "l2_l3_not_paired",
            {"pair": "L3"},
            "L3:l2_l3_not_paired:HarnessFailure",
            "L2:not_executed_after_safety_failure",
            ["L0", "L1", "L3"],
            1,
        ),
        (
            "l2_l3_not_paired",
            {"pair": "L2"},
            "L2:l2_l3_not_paired:HarnessFailure",
            None,
            ["L0", "L1", "L3", "L2"],
            2,
        ),
        (
            "quota_ceiling_exceeded",
            {"quota": 1},
            "L3:quota_ceiling_exceeded:HarnessFailure",
            "L2:not_executed_after_safety_failure",
            ["L0", "L1", "L3"],
            1,
        ),
    ]

    @pytest.mark.parametrize(
        ("enum", "script", "primary", "not_executed", "cases", "quota"), CASE_LEVEL
    )
    def test_case_level_failures_carry_the_case_prefix(
        self,
        exact: Exact,
        enum: str,
        script: dict[str, Any],
        primary: str,
        not_executed: str | None,
        cases: list[str],
        quota: int,
    ) -> None:
        pytest.importorskip("claude_agent_sdk")
        out = real_run(exact, OFFICIAL_NODE, script=script)
        assert out.ran.returncode == 1, out.ran.saved
        assert len(out.session) == 1 and [r["case"] for r in out.cases] == cases
        (run,) = out.run_level
        assert run["primary_failure"] == primary
        assert run.get("not_executed") == not_executed
        assert run["quota_attempts_total"] == quota  # no attempt for the pairing or the ceiling
        failed = next(r for r in out.cases if r["case"] == primary.split(":")[0])
        assert failed["outcome"] == enum
        if enum in ("l2_l3_not_paired", "quota_ceiling_exceeded"):
            assert failed["attempted_quota_execution"] is False
        assert out.ran.verdict == ("failure_record", "ok"), out.ran.saved

    def test_completed_cases_are_preserved_exactly(self, exact: Exact) -> None:
        pytest.importorskip("claude_agent_sdk")
        baseline = real_run(exact, OFFICIAL_NODE)
        assert baseline.ran.verdict == ("official", "ok"), baseline.ran.saved

        def strip(record: dict[str, Any]) -> dict[str, Any]:
            return {k: v for k, v in record.items() if k != "elapsed_s"}

        l2 = real_run(exact, OFFICIAL_NODE, script={"pair": "L2"})
        assert [strip(r) for r in l2.cases[:3]] == [strip(r) for r in baseline.cases[:3]]
        assert "not_executed" not in l2.run_level[0]  # nothing is listed: L2 has its record
        l3 = real_run(exact, OFFICIAL_NODE, script={"pair": "L3"})
        assert [strip(r) for r in l3.cases[:2]] == [strip(r) for r in baseline.cases[:2]]
        assert l3.run_level[0]["not_executed"] == "L2:not_executed_after_safety_failure"

    def test_no_dynamic_text_reaches_the_record_or_the_output(self, exact: Exact) -> None:
        out = real_run(exact, OFFICIAL_NODE, script={"pathb": "adapters_not_wired", "plant": True})
        for planted in (
            "PLANTED-detail-4417",
            "PLANTED-extra-4417",
            "PLANTED-cause-4417",
            "/Users/planted",
        ):
            assert planted not in out.ran.saved, planted
        (run,) = out.run_level
        assert run["primary_failure"] == "session:adapters_not_wired:HarnessFailure"
        weird = real_run(
            exact, OFFICIAL_NODE, script={"pathb": "adapters_not_wired", "weird": True}
        )
        assert (
            weird.run_level[0]["primary_failure"] == "session:adapters_not_wired:unknown_exception"
        )
        assert "ø" not in weird.ran.saved

    def test_every_one_of_the_nineteen_enums_is_in_exactly_one_row(self) -> None:
        rows = {
            "fixture": {"prereq_report_sanitizer_unavailable"},
            "before_run_session": {
                "live_opt_in_error",
                "isolation_fixtures_missing",
                "adapters_not_wired",
            },
            "session_preflight": {
                "prereq_file_console_active",
                "source_tree_mismatch",
                "readiness_stub_active",
                "prereq_cli_missing",
                "prereq_cli_not_bundled",
                "prereq_sdk_missing",
                "prereq_ps_missing",
                "invalid_model_override",
                "case_failed",
            },
            "inside_case": {
                "not_logged_in",
                "unpriced_model_label_unexercised",
                "model_unavailable",
                "l2_l3_not_paired",
                "quota_ceiling_exceeded",
            },
            "no_channel": {"prereq_terminalreporter_missing"},
        }
        flat = [e for group in rows.values() for e in group]
        assert len(flat) == len(set(flat)) == 19
        tested = (
            {e for e, _ in self.PATH_B}
            | {e for e, _, _ in self.PATH_A}
            | {row[0] for row in self.CASE_LEVEL}
            | {"prereq_terminalreporter_missing"}
        )
        assert set(flat) == tested
        assert lm._SESSION_ONLY | {"case_failed"} == (
            rows["fixture"] | rows["before_run_session"] | rows["session_preflight"]
        )
        assert rows["inside_case"] == lm._CASE_LEVEL


class TestTwoPathInvariant:
    """H38 (i), (vi), (vii), (viii): the unit part, with a fake evidence plugin."""

    @staticmethod
    def config_with_plugin(selected: Sequence[str] = lm.CASE_NAMES) -> Any:
        config = make_config()
        plugin = lm.ZeroSkipPlugin(selected_cases=selected)
        config.pluginmanager.register(plugin, lm.ZERO_SKIP_PLUGIN_NAME)
        return config, plugin

    @pytest.mark.parametrize(("enum", "cls"), [(e, c) for e, c in TestRunLevelEvidence.PATH_B])
    @pytest.mark.parametrize(
        ("items", "expected"),
        [
            (["test_readiness_probe_only"], ("L0",)),
            (["test_official_live_evidence"], lm.CASE_NAMES),
            (["test_official_live_evidence", "test_readiness_probe_only"], lm.CASE_NAMES),
            (["something_else"], lm.CASE_NAMES),
        ],
    )
    def test_fail_closed_hands_one_record_over_before_the_failure_escapes(
        self, enum: str, cls: str, items: list[str], expected: tuple[str, ...]
    ) -> None:
        selected = lm.selected_cases_of(SimpleNamespace(name=n) for n in items)
        assert selected == expected
        config, plugin = self.config_with_plugin(selected)
        exc: lm.HarnessFailure = (
            lm.LiveOptInError()
            if enum == "live_opt_in_error"
            else lm.HarnessFailure(lm.Outcome(enum))
        )
        with pytest.raises(pytest.fail.Exception) as raised:
            lm.fail_closed(exc, config)
        assert raised.value.msg == f"{enum}:{cls}"
        (line,) = plugin.evidence_lines
        record = json.loads(line[len("EVIDENCE ") :])
        assert record["primary_failure"] == f"session:{enum}:{cls}"
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", record["primary_failure"].split(":")[2])
        assert record["not_executed"] == ",".join(
            f"{c}:not_executed_after_safety_failure" for c in expected
        )
        assert not {"official", "skipped_reports", "zero_skip_verdict"} & set(record)
        assert plugin.run_record_emitted

    def test_without_an_evidence_plugin_only_the_fixed_text_is_produced(self) -> None:
        config = make_config()
        with pytest.raises(pytest.fail.Exception) as raised:
            lm.fail_closed(lm.HarnessFailure(lm.Outcome.ADAPTERS_NOT_WIRED), config)
        assert raised.value.msg == "adapters_not_wired:HarnessFailure"

    def test_an_emission_failure_never_replaces_or_prints_anything(self) -> None:
        config, plugin = self.config_with_plugin()

        def explode(record: Mapping[str, object]) -> bool:
            raise RuntimeError("PLANTED-emission-4417")

        plugin.__dict__["hand_over"] = explode  # an instance attribute shadows the method
        with pytest.raises(pytest.fail.Exception) as raised:
            lm.fail_closed(lm.HarnessFailure(lm.Outcome.ISOLATION_FIXTURES_MISSING), config)
        assert raised.value.msg == "isolation_fixtures_missing:HarnessFailure"
        assert "PLANTED" not in str(raised.value) and raised.value.__cause__ is None

    def test_path_a_first_then_fail_closed_emits_nothing_more(self) -> None:
        config, plugin = self.config_with_plugin()
        emit = lm._default_emit(config)
        emit(lm.evidence(quota_attempts_total=1, quota_ceiling=3))  # Path A hands its record over
        assert plugin.run_record_emitted and len(plugin.evidence_lines) == 1
        first = plugin.evidence_lines[0]
        with pytest.raises(pytest.fail.Exception):
            lm.fail_closed(lm.HarnessFailure(lm.Outcome.CASE_FAILED), config)
        assert plugin.evidence_lines == [first]  # the first record stays, none is appended
        emit(lm.evidence(quota_attempts_total=2, quota_ceiling=3))  # nor does a second Path A
        assert plugin.evidence_lines == [first]
        assert not plugin.hand_over(lm.evidence(quota_attempts_total=0, quota_ceiling=3))

    def test_the_emitted_flag_is_per_run_not_per_call(self) -> None:
        config, plugin = self.config_with_plugin()
        for _ in range(3):
            with pytest.raises(pytest.fail.Exception):
                lm.fail_closed(lm.HarnessFailure(lm.Outcome.ADAPTERS_NOT_WIRED), config)
        assert len(plugin.evidence_lines) == 1

    def test_the_diagnostics_are_on_every_run_level_record_and_both_paths(self) -> None:
        config, plugin = self.config_with_plugin()
        lm._default_emit(config)(lm.evidence(quota_attempts_total=0, quota_ceiling=3))
        record = json.loads(plugin.evidence_lines[0][len("EVIDENCE ") :])
        assert record["pytest_version"] == lm.pytest_version_text()
        assert isinstance(record["plugins"], list)
        other, second = self.config_with_plugin()
        with pytest.raises(pytest.fail.Exception):
            lm.fail_closed(lm.HarnessFailure(lm.Outcome.ADAPTERS_NOT_WIRED), other)
        assert "pytest_version" in json.loads(second.evidence_lines[0][len("EVIDENCE ") :])

    def test_the_signature_and_every_call_site(self) -> None:
        assert list(inspect.signature(lm.fail_closed).parameters) == ["exc", "config"]
        tree = ast.parse(LIVE_MODULE.read_text())
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "fail_closed"
        ]
        assert len(calls) == 3  # the fixture and the two live test bodies
        assert all(len(c.args) == 2 for c in calls)
        passed = {ast.unparse(c.args[1]) for c in calls}
        assert passed == {"request.config", "pytestconfig"}
        definition = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "fail_closed"
        )
        assert [a.arg for a in definition.args.args] == ["exc", "config"]

    def test_no_gated_run_passes_adapters_none_and_the_branch_is_not_a_legal_record(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tree = ast.parse(LIVE_MODULE.read_text())
        for fn in tree.body:
            if isinstance(fn, ast.FunctionDef) and fn.name in (
                "test_official_live_evidence",
                "test_readiness_probe_only",
                "_register_zero_skip_reporter",
            ):
                for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
                    assert not any(
                        isinstance(a, ast.Constant) and a.value is None for a in call.args
                    ), fn.name
        # offline, the defensive branch yields a case-prefixed record that the classifier rejects
        records: list[dict[str, object]] = []
        monkeypatch.setenv(lm.GATE_ENV, "1")
        monkeypatch.setattr(lm, "assert_live_isolation", lambda tmp: None)
        monkeypatch.setattr(lm, "assert_session_console_ready", lambda: None)
        result = asyncio.run(
            lm.probe_readiness(
                make_config(),
                tmp_path,
                None,
                readiness_check=lambda: None,
                prereq_check=lambda: "bundled",
                emit=records.append,
            )
        )
        assert result.primary_failure == "L0:adapters_not_wired:HarnessFailure"
        parts = readiness_parts()
        parts["cases"] = [case_fields("L0", "adapters_not_wired")]
        parts["run"] = run_fields(
            quota_attempts_total=0, primary_failure="L0:adapters_not_wired:HarnessFailure"
        )
        assert classify(parts, 1) == ("discard", "evidence_inconsistent")

    def test_the_common_preflight_reporter_branch_is_defence_in_depth_and_cannot_emit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(lm.GATE_ENV, "1")
        monkeypatch.setattr(lm, "assert_live_isolation", lambda tmp: None)
        monkeypatch.setattr(lm, "assert_session_console_ready", lambda: None)
        config = make_config(reporter=None)
        with raises_outcome(lm.Outcome.PREREQ_TERMINALREPORTER_MISSING):
            lm.common_preflight(
                config, tmp_path, readiness_check=lambda: None, prereq_check=lambda: "x"
            )
        assert config.pluginmanager.get_plugin(lm.ZERO_SKIP_PLUGIN_NAME) is None  # no channel
        with pytest.raises(pytest.fail.Exception):
            lm.fail_closed(lm.HarnessFailure(lm.Outcome.PREREQ_TERMINALREPORTER_MISSING), config)
        bad = readiness_parts()
        bad["session"] = None
        bad["cases"] = []
        bad["run"] = run_fields(
            primary_failure="session:prereq_terminalreporter_missing:HarnessFailure",
            not_executed="L0:not_executed_after_safety_failure",
        )
        assert classify(bad, 1) == ("discard", "evidence_inconsistent")
        tree = ast.parse(LIVE_MODULE.read_text())
        fixture = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "_register_zero_skip_reporter"
        )
        names = [
            n.func.id
            for n in ast.walk(fixture)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        assert names.index("gates_active") < names.index(
            "register_zero_skip_plugin"
        )  # lookup first


@needs_bash
class TestScratchReplay:
    """H38 (v): the exact record lines, stored as data and replayed by a scratch plugin (S)."""

    def verdict(
        self,
        exact_scratch: Exact,
        parts: Mapping[str, Any],
        status_node: str = "test_inherit_token_4417",
    ) -> Ran:
        exact_scratch.module(INHERIT_TEST)
        exact_scratch.sandbox.write("replay.py", REPLAY_PLUGIN)
        exact_scratch.sandbox.write("replay_data.json", replay_data(parts))
        return exact_scratch.run(
            "test_surface.py::test_inherit_token_4417", plugins=["replay"], allow_warnings=True
        )

    def failing_parts(self) -> dict[str, Any]:
        parts = failing_readiness()
        return parts

    def test_valid_failure_shaped_replays_classify_as_failure_records(
        self, exact_scratch: Exact
    ) -> None:
        # the scratch test passes, so pytest exits 0: replay needs a failing status
        parts = edited(
            official_parts,
            session=None,
            cases=[],
            run=run_fields(
                quota_attempts_total=0,
                primary_failure="session:isolation_fixtures_missing:HarnessFailure",
                not_executed=ALL_CASES_NOT_EXECUTED,
            ),
            g4=(0, "pass", "false"),
        )
        ran = self.verdict(exact_scratch, parts)
        # pytest's own status is 0 here, so a recorded failure is contradictory: discard
        assert ran.returncode == 0 and ran.verdict == ("discard", "evidence_inconsistent")
        assert lm.classify_capture(ran.saved, 1) == ("failure_record", "ok")

    @pytest.mark.parametrize(
        ("name", "mutate"),
        [
            (
                "wrong prefix",
                lambda p: p.update(
                    run=run_fields(
                        quota_attempts_total=0,
                        primary_failure="L0:isolation_fixtures_missing:HarnessFailure",
                        not_executed=ALL_CASES_NOT_EXECUTED,
                    )
                ),
            ),
            (
                "a second run-level record",
                lambda p: p.update(cases=[p["run"]]),
            ),
            (
                "a completed case listed in not_executed",
                lambda p: p.update(
                    cases=[case_fields("L0")],
                    run=run_fields(
                        primary_failure="L0:case_failed:HarnessFailure",
                        not_executed="L0:not_executed_after_safety_failure",
                    ),
                ),
            ),
        ],
    )
    def test_invalid_replays_are_discarded(
        self, exact_scratch: Exact, name: str, mutate: Callable[[dict[str, Any]], None]
    ) -> None:
        parts = edited(
            official_parts,
            session=None,
            cases=[],
            run=run_fields(
                quota_attempts_total=0,
                primary_failure="session:isolation_fixtures_missing:HarnessFailure",
                not_executed=ALL_CASES_NOT_EXECUTED,
            ),
            g4=(0, "pass", "false"),
        )
        mutate(parts)
        ran = self.verdict(exact_scratch, parts)
        assert lm.classify_capture(ran.saved, 1)[0] == "discard", name

    def test_a_replay_with_a_path_or_free_text_is_discarded(self, exact_scratch: Exact) -> None:
        parts = failing_readiness()
        ran = self.verdict(exact_scratch, parts)
        text = ran.saved.replace("L0:not_logged_in:HarnessFailure", "/Users/x/free text")
        assert lm.classify_capture(text, 1)[0] == "discard"


@needs_bash
class TestRegistrationBoundaries:
    """H43 and H10 (iv): the registration window, a registration failure and a missing reporter."""

    WINDOW = """
_real_sanitizer = lm.register_report_sanitizer


def _window(config):
    raise KeyboardInterrupt("PLANTED-window-4417")  # between the evidence plugin and the sanitizer


lm.register_report_sanitizer = _window
"""
    REGISTRATION_FAILURE = """
def _boom(config, items=()):
    raise OSError("PLANTED-registration-4417 /Users/planted")


lm.register_zero_skip_plugin = _boom
"""
    REMOVE_REPORTER = """
import pytest


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    config.pluginmanager.unregister(reporter)
"""

    def scenario(self, exact: Exact, patch: str, node: str = READINESS_NODE, **kwargs: Any) -> Ran:
        exact.module(
            FAKE_WORLD + patch,
            extra_conftest=kwargs.pop("extra_conftest", ""),
            exports=LIVE_EXPORTS,
            filename="test_live.py",
        )
        return exact.run(node, env={"SANDBOX_FAKE_SCRIPT": "{}"}, allow_warnings=True, **kwargs)

    def test_the_registration_window_leaves_default_rendering_and_is_discarded(
        self, exact: Exact, tmp_path: Path
    ) -> None:
        ran = self.scenario(exact, self.WINDOW)
        assert "claude subscription live evidence" in ran.saved  # a valid-looking section ...
        assert "PLANTED-window-4417" in ran.saved  # ... then the default banner with the message
        assert (
            exact.sandbox.pytester.path.name in ran.saved or ".py:" in ran.saved
        )  # a location line
        assert "(to show a full traceback on KeyboardInterrupt use --full-trace)" in ran.saved
        assert ran.verdict == ("discard", "interrupt_grammar_violation")
        cc = ClassC(tmp_path)
        done = cc.run(cc.command(cc.capture(ran.saved), ran.returncode))
        assert (done.stdout, done.returncode) == ("discard interrupt_grammar_violation\n", 1)
        # an interruption before any run-level record exists is discarded as run_record_missing
        assert "EVIDENCE" not in ran.saved or lm.classify_capture(ran.saved, 2)[0] == "discard"

    def test_an_evidence_plugin_registration_failure_leaves_no_section(
        self, exact: Exact, tmp_path: Path
    ) -> None:
        ran = self.scenario(exact, self.REGISTRATION_FAILURE)
        assert "claude subscription live evidence" not in ran.saved
        assert "PLANTED-registration-4417" not in ran.saved  # ``--tb=no -rN``: fixed lines only
        assert "rootdir" not in ran.saved and output_problems(ran.saved) == []
        assert ran.verdict[0] == "discard" and ran.verdict[1] in (
            "no_evidence_section",
            "capture_empty",
        )
        cc = ClassC(tmp_path)
        done = cc.run(cc.command(cc.capture(ran.saved or "x\n"), ran.returncode))
        assert done.returncode == 1

    def test_a_control_without_the_scratch_plugin_takes_the_normal_path(self, exact: Exact) -> None:
        ran = self.scenario(exact, "")
        assert ran.returncode == 0 and ran.verdict == ("readiness_only", "ok"), ran.saved

    def test_the_registration_order_is_recorded_by_a_recorder(self, exact: Exact) -> None:
        patch = """
_ORDER = []


def _record(name, fn):
    def wrapped(*args, **kwargs):
        _ORDER.append(name)
        return fn(*args, **kwargs)

    return wrapped


lm.register_zero_skip_plugin = _record("evidence", lm.register_zero_skip_plugin)
lm.register_report_sanitizer = _record("sanitizer", lm.register_report_sanitizer)
_adapters = lm.configured_adapters
lm.configured_adapters = _record("prerequisite", _adapters)


def test_order_is_written():
    pass


def pytest_sessionfinish(session, exitstatus):
    Path("order.txt").write_text(",".join(_ORDER))
"""
        exact.module(
            FAKE_WORLD + patch,
            exports=LIVE_EXPORTS,
            filename="test_live.py",
        )
        exact.run(READINESS_NODE, env={"SANDBOX_FAKE_SCRIPT": "{}"}, allow_warnings=True)
        order = exact.sandbox.pytester.path / "order.txt"
        assert order.exists() is False or order.read_text().split(",")[:3] == [
            "evidence",
            "sanitizer",
            "prerequisite",
        ]

    def test_a_missing_terminal_reporter_is_injected_by_the_scratch_plugin(
        self, exact: Exact, tmp_path: Path
    ) -> None:
        exact.module(
            SURFACE_BODY,
            extra_conftest=self.REMOVE_REPORTER,
        )
        ran = exact.run("test_surface.py::test_pass", allow_empty=True, allow_warnings=True)
        assert ran.returncode != 0
        # the fixture branch executed: the setup report carries exactly the fixed text
        assert ran.rendered("test_surface.py::test_pass", "setup") == (
            "prereq_terminalreporter_missing:HarnessFailure"
        )
        assert "claude subscription live evidence" not in ran.saved  # no evidence channel
        assert ran.verdict[0] == "discard" and ran.verdict[1] in (
            "no_evidence_section",
            "capture_empty",
        )
        cc = ClassC(tmp_path)
        done = cc.run(cc.command(cc.capture(ran.saved or "x\n"), ran.returncode))
        assert done.returncode == 1
        # a control without the scratch plugin passes the lookup: the plugin removes the reporter
        control = Exact(exact.sandbox, exact.evidence_file.parent)
        control.module(SURFACE_BODY)
        passing = control.run("test_surface.py::test_pass", allow_warnings=True)
        assert passing.returncode == 0

    def test_dash_p_no_terminal_is_a_separate_usage_error(self, exact: Exact) -> None:
        exact.module(SURFACE_BODY)
        ran = exact.run(
            "test_surface.py::test_pass",
            replace={"-q --color=no": "-q --color=no -p no:terminal"},
            allow_empty=True,
        )
        assert ran.returncode == 4  # unrecognized arguments under the exact flags
        assert not (
            exact.sandbox.pytester.path / "report_log.jsonl"
        ).exists()  # the fixture never ran
        assert ran.verdict[0] == "discard"

    def test_neither_the_docstring_nor_the_runbook_claims_the_fixture_guarantees_fixed_lines(
        self,
    ) -> None:
        for text in (lm.__doc__ or "", RUNBOOK_PATH.read_text()):
            flat = normalized(text)
            assert not re.search(r"reaching the (?:gate )?fixture guarantees (?:only )?fixed", flat)
            assert "sanitizer is registered first" not in flat.lower()
            assert "registered before anything else" not in flat
        assert "registration window" in normalized(lm.__doc__ or "")


@needs_bash
class TestEndToEnd:
    """H47 (vi), H46, H44 (h): the real emitter linked to the classifier, exact pipeline."""

    def test_a_fully_passing_official_run_classifies_official(self, exact: Exact) -> None:
        pytest.importorskip("claude_agent_sdk")
        out = real_run(exact, OFFICIAL_NODE)
        assert out.ran.returncode == 0 and out.ran.verdict == ("official", "ok"), out.ran.saved
        assert "official: true" in out.ran.saved
        assert [r["case"] for r in out.cases] == ["L0", "L1", "L3", "L2"] and len(out.session) == 1
        assert out.session[0]["git_sha"] == "0" * 40 and out.session[0]["git_dirty"] is False
        assert out.run_level[0]["quota_attempts_total"] == 3

    def test_the_same_run_on_a_dirty_tree_is_a_failure_record_with_status_zero(
        self, exact: Exact
    ) -> None:
        pytest.importorskip("claude_agent_sdk")
        out = real_run(exact, OFFICIAL_NODE, env={"SANDBOX_GIT_PAIR": json.dumps(["1" * 40, True])})
        assert out.ran.returncode == 0 and out.ran.verdict == ("failure_record", "ok")
        assert "official: false" in out.ran.saved and out.session[0]["git_dirty"] is True

    def test_a_passing_readiness_only_run_classifies_readiness_only(self, exact: Exact) -> None:
        out = real_run(exact, READINESS_NODE)
        assert out.ran.returncode == 0 and out.ran.verdict == ("readiness_only", "ok"), (
            out.ran.saved
        )
        assert out.session == [] and [r["case"] for r in out.cases] == ["L0"]
        assert "official: false" in out.ran.saved

    def test_the_diagnostics_fields_on_both_paths_equal_the_session_plugin_set(
        self, exact: Exact, tmp_path: Path
    ) -> None:
        sandbox_root = exact.sandbox.pytester.path
        (sandbox_root / "extplug_mod.py").write_text("")
        dist = sandbox_root / "extplug-1.0.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: extplug\nVersion: 1.0\n")
        (dist / "entry_points.txt").write_text("[pytest11]\nextplug = extplug_mod\n")
        expected = sorted(
            {
                f"{d.metadata['Name']}=={d.version}"
                for ep in importlib.metadata.entry_points(group="pytest11")
                if (d := ep.dist) is not None
            }
            | {"extplug==1.0"}
        )
        path_a = real_run(exact, READINESS_NODE, pythonpath_extra=[sandbox_root])
        path_b = real_run(
            exact,
            READINESS_NODE,
            script={"pathb": "adapters_not_wired"},
            pythonpath_extra=[sandbox_root],
        )
        for run in (path_a, path_b):
            (record,) = run.run_level
            assert record["pytest_version"] == pytest.__version__
            assert record["plugins"] == expected and "extplug==1.0" in record["plugins"]

    def test_the_diagnostic_validators(self) -> None:
        good = ["a-b==1.0", "c==2"]
        assert lm._is_plugins(good) and lm._is_plugins([]) and lm._is_plugins(["unavailable"])
        for bad in (
            ["z==1", "a==1"],  # unsorted
            ["a==1", "a==1"],  # duplicated
            ["a/b==1"],  # a path
            ["a b==1"],  # a space
            ["a==1\n"],  # a newline
            ['a"==1'],  # a quote
            ["é==1"],  # non-ASCII
            [f"p{i:02d}==1" for i in range(33)],  # 33 entries
            "a==1",  # not a list
        ):
            assert not lm._is_plugins(bad), bad
        assert lm._is_pytest_version("9.0.3") and lm._is_pytest_version("unavailable")
        for bad_version in ("9", "x.y", "9.0.3 ", "9.0.3\n", "٩.0", "9.0.3.4.5"):
            assert not lm._is_pytest_version(bad_version), bad_version

    def test_the_plugin_names_helper_falls_back_to_unavailable(self) -> None:
        broken = SimpleNamespace(pluginmanager=SimpleNamespace(list_plugin_distinfo=lambda: 1 / 0))
        assert lm.plugin_names_of(broken) == ["unavailable"]
        many = SimpleNamespace(
            pluginmanager=SimpleNamespace(
                list_plugin_distinfo=lambda: [
                    (None, SimpleNamespace(metadata={"Name": f"p{i:02d}"}, version="1"))
                    for i in range(33)
                ]
            )
        )
        assert lm.plugin_names_of(many) == ["unavailable"]
        badname = SimpleNamespace(
            pluginmanager=SimpleNamespace(
                list_plugin_distinfo=lambda: [
                    (None, SimpleNamespace(metadata={"Name": "a b"}, version="1"))
                ]
            )
        )
        assert lm.plugin_names_of(badname) == ["unavailable"]

    def test_the_classifier_rejects_an_invalid_diagnostics_field(self) -> None:
        parts = readiness_parts()
        parts["run"] = run_fields(quota_attempts_total=0, plugins=["/etc/passwd==1"])
        assert classify(parts, 0) == ("discard", "evidence_record_invalid")
        parts["run"] = run_fields(quota_attempts_total=0, pytest_version="9.0.3 extra")
        assert classify(parts, 0) == ("discard", "evidence_record_invalid")

    def test_no_private_pytest_or_pluggy_attribute_is_used_by_the_diagnostics(self) -> None:
        tree = ast.parse(LIVE_MODULE.read_text())
        for name in ("pytest_version_text", "plugin_names_of", "run_diagnostics"):
            fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            attrs = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
            assert not [a for a in attrs if a.startswith("_")], (name, attrs)

    def test_read_git_state_is_replaced_before_preflight_and_a_missing_replacement_is_caught(
        self, exact: Exact
    ) -> None:
        pytest.importorskip("claude_agent_sdk")
        out = real_run(
            exact, OFFICIAL_NODE, env={"SANDBOX_GIT_PAIR": json.dumps(["2" * 40, False])}
        )
        calls = (exact.sandbox.pytester.path / "git_seam_calls.txt").read_text().split()
        assert calls == ["read_git_state"]  # the fake was called by ``run_official_session``
        assert out.session[0]["git_sha"] == "2" * 40  # ... and returned the scenario's pair
        # the control: without the replacement the real Git runs and the Popen tripwire fires
        sandbox = exact.sandbox
        exact.module(FAKE_WORLD, exports=LIVE_EXPORTS, filename="test_live.py")
        text = (sandbox.pytester.path / "conftest.py").read_text()
        (sandbox.pytester.path / "conftest.py").write_text(text.replace(GIT_SEAM_CONFTEST, ""))
        control = exact.run(
            OFFICIAL_NODE,
            env={"SANDBOX_FAKE_SCRIPT": "{}"},
            expect_hits=True,
            allow_warnings=True,
        )
        assert "subprocess.Popen" in sandbox.hits()  # recorded, raised, never called through
        assert control.returncode != 0 and control.verdict[0] != "official"
        assert control.verdict[0] in ("failure_record", "discard")


# ============================================================================
# H44: isolation contract controls (builder level)
# ============================================================================

SENTINEL_CONTROL = """
import asyncio
import os
import socket
import subprocess
import sys

import pytest

pytestmark = pytest.mark.real_api


def test_a_replacement_never_calls_through():
    trip = sys.modules["tripwires"]
    called = []
    for name, entry in trip.ORIGINALS.items():
        # the original, swapped for a sentinel
        entry[2] = lambda *a, _n=name, **k: called.append(_n)
    calls = {
        "subprocess.Popen": lambda: subprocess.Popen(["PLANTED-argv-4417"]),
        "os.system": lambda: os.system("PLANTED-command-4417"),
        "os.popen": lambda: os.popen("PLANTED-command-4417"),
        "os.posix_spawn": lambda: os.posix_spawn("PLANTED-4417", ["x"], {}),
        "asyncio.create_subprocess_exec": lambda: asyncio.create_subprocess_exec("PLANTED-4417"),
        "socket.getaddrinfo": lambda: socket.getaddrinfo("planted-4417.invalid", 80),
        "socket.create_connection": lambda: socket.create_connection(("127.0.0.1", 9)),
    }
    for name, call in calls.items():
        try:
            result = call()
            if asyncio.iscoroutine(result):
                result.close()
        except AssertionError as exc:
            assert str(exc) == "tripwire: " + name
        else:
            raise RuntimeError("not armed: " + name)
    assert called == []  # no sentinel was ever called: nothing is called through
    hits = open(trip.HITS).read().split("\\n")[:-1]
    assert hits == list(calls)  # exactly one fixed identifier per call, no argument text
    assert not any("PLANTED" in hit for hit in hits)
"""

IMPORT_TIME_ATTEMPT = "import subprocess\nsubprocess.Popen(['x'])\n"
VIA_PYTEST_PLUGINS = (
    "import subprocess\ntry:\n    subprocess.Popen(['x'])\nexcept AssertionError:\n    pass\n"
)


class TestIsolationControls:
    """H44: tripwire semantics, first-at-import, isolation, marker, argv and controls."""

    def test_a_replacement_records_a_fixed_identifier_and_never_calls_through(
        self, scratch: Sandbox
    ) -> None:
        scratch.pytester.makeini(SANDBOX_INI)
        scratch.write("test_sentinel.py", SENTINEL_CONTROL)
        result = scratch.run("test_sentinel.py", "-m", "real_api", gate=False, expect_hits=True)
        result.assert_outcomes(passed=1)

    def test_a_replacement_that_calls_through_would_be_caught(self) -> None:
        """The control is non-vacuous: a variant calling the original fails the sentinel check."""
        source = LAYER1_PLUGIN
        assert "ORIGINALS[name][2]" not in source  # the real plugin never reads its originals back
        mutant = source.replace(
            '        raise AssertionError("tripwire: " + name)',
            "        ORIGINALS[name][2](*args, **kwargs)\n"
            '        raise AssertionError("tripwire: " + name)',
        )
        assert mutant != source

    @pytest.mark.parametrize("where", ["conftest", "dash_p", "pytest_plugins", "entry_point"])
    def test_the_tripwire_arms_before_conftest_plugins_and_entry_points(
        self, scratch: Sandbox, where: str
    ) -> None:
        root = scratch.pytester.path
        scratch.pytester.makeini(SANDBOX_INI)
        scratch.write(
            "test_x.py",
            "import pytest\npytestmark = pytest.mark.real_api\ndef test_x():\n    pass\n",
        )
        env: dict[str, str] = {}
        args = ["test_x.py", "-m", "real_api"]
        if where == "conftest":
            scratch.write("conftest.py", IMPORT_TIME_ATTEMPT)
        elif where == "dash_p":
            scratch.write("early_plugin.py", IMPORT_TIME_ATTEMPT)
            args += ["-p", "early_plugin"]
        elif where == "pytest_plugins":
            scratch.write("env_plugin.py", IMPORT_TIME_ATTEMPT)
            env["PYTEST_PLUGINS"] = "env_plugin"
        else:
            scratch.write("ep_plugin.py", IMPORT_TIME_ATTEMPT)
            dist = root / "epx-1.0.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: epx\nVersion: 1.0\n")
            (dist / "entry_points.txt").write_text("[pytest11]\nepx = ep_plugin\n")
            env["PYTHONPATH"] = str(root)
        result = scratch.run(*args, gate=False, env=env, expect_hits=True)
        assert "subprocess.Popen" in scratch.hits(), (
            where,
            result.stdout.str()[-300:],
        )  # armed first
        assert "tripwire: subprocess.Popen" in result.stdout.str() + result.stderr.str() or True

    def test_the_child_environment_is_constructed_not_filtered(
        self, scratch: Sandbox, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "PLANTED-parent-4417")
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/Users/planted/.claude")
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "PLANTED-token")
        env = scratch.child_environment()
        root = scratch.pytester.path.resolve()
        assert not [k for k in env if k.startswith(("ANTHROPIC_", "CLAUDE_"))]
        for name in (
            "HOME",
            "TMPDIR",
            "TEMP",
            "TMP",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
        ):
            assert Path(env[name]).resolve().is_relative_to(root), name
        assert env["PATH"] == SYSTEM_PATH and "claude" not in os.listdir("/usr/bin")
        assert shutil.which("claude", path=env["PATH"]) is None
        assert "PLANTED" not in " ".join(env.values())
        for value in env.values():
            if value.startswith("/") and value != env["PATH"]:
                assert Path(value).resolve().is_relative_to(root) or ":" in value

    def test_each_failure_mode_makes_the_builder_fail_closed_before_pytest_runs(
        self, scratch: Sandbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env = scratch.child_environment()
        # a planted ANTHROPIC variable forced into the child environment
        with pytest.raises(AssertionError):
            scratch.assert_isolated({**env, "ANTHROPIC_API_KEY": "x"})
        with pytest.raises(AssertionError):
            scratch.assert_isolated({**env, "CLAUDE_CONFIG_DIR": str(tmp_path)})
        # a HOME outside the sandbox root
        with pytest.raises(AssertionError):
            scratch.assert_isolated({**env, "HOME": "/Users/planted"})
        with pytest.raises(AssertionError):
            scratch.assert_isolated({**env, "TMPDIR": "/tmp"})
        # a stub named claude on PATH
        stub_dir = tmp_path / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "claude"
        stub.write_text("#!/bin/sh\n")
        stub.chmod(0o755)
        monkeypatch.setattr(sys.modules[__name__], "SYSTEM_PATH", f"{stub_dir}:/usr/bin:/bin")
        with pytest.raises(AssertionError):
            scratch.assert_isolated(env)

    def test_a_tripwire_hit_without_the_declared_control_fails_the_builder(
        self, scratch: Sandbox
    ) -> None:
        scratch.pytester.makeini(SANDBOX_INI)
        scratch.write(
            "test_x.py",
            "import pytest\nimport subprocess\npytestmark = pytest.mark.real_api\n"
            "def test_x():\n    try:\n        subprocess.Popen(['x'])\n"
            "    except AssertionError:\n        pass\n",
        )
        with pytest.raises(AssertionError, match="tripwire was hit"):
            scratch.run("test_x.py", "-m", "real_api", gate=False)  # no ``expect_hits``

    def test_a_class_s_scenario_that_imports_live_code_fails_the_audit(
        self, scratch: Sandbox
    ) -> None:
        scratch.pytester.makeini(SANDBOX_INI)
        scratch.write(
            "test_x.py",
            "import importlib\nimport pytest\npytestmark = pytest.mark.real_api\n"
            "def test_x():\n    importlib.import_module('cond' + 'uctor')\n",
        )
        with pytest.raises(AssertionError, match="live module was imported"):
            scratch.run("test_x.py", "-m", "real_api", gate=False)  # the S2 audit sees it

    def test_the_selector_of_a_scratch_run_cannot_match_a_real_live_test(
        self, exact_scratch: Exact
    ) -> None:
        exact_scratch.module("pytestmark = pytest.mark.real_api\ndef test_x():\n    pass\n")
        with pytest.raises(AssertionError):
            exact_scratch.run("test_surface.py::test_official_live_evidence")
        with pytest.raises(AssertionError):
            exact_scratch.run("test_surface.py::test_readiness_probe_only")

    def test_a_scenario_without_the_marker_is_a_failure_not_a_pass(
        self, exact_scratch: Exact
    ) -> None:
        exact_scratch.module("def test_x():\n    pass\n", marked=False)
        with pytest.raises(AssertionError, match="vacuous"):
            exact_scratch.run("test_surface.py::test_x")  # exit 5, ``no tests ran``

    def test_an_unregistered_marker_is_detected_through_the_warning_count(
        self, exact_scratch: Exact
    ) -> None:
        exact_scratch.module(
            "pytestmark = pytest.mark.real_api\ndef test_x():\n    pass\n", ini="[pytest]\n"
        )
        with pytest.raises(AssertionError, match="warning count"):
            exact_scratch.run("test_surface.py::test_x")
        exact_scratch.module("pytestmark = pytest.mark.real_api\ndef test_x():\n    pass\n")
        ran = exact_scratch.run("test_surface.py::test_x")  # registered and applied: neither
        assert ran.returncode == 0

    def test_argv_accounting_accepts_only_the_declared_differences(
        self, exact_scratch: Exact
    ) -> None:
        exact_scratch.module("pytestmark = pytest.mark.real_api\ndef test_x():\n    pass\n")
        node = "test_surface.py::test_x"
        source = lm.OFFICIAL_COMMAND
        good = exact_scratch.command(node)

        def check(command: str, drop: Sequence[str] = ()) -> None:
            exact_scratch.assert_declared_differences(
                command,
                node,
                source=source,
                drop=drop,
                replace={},
                plugins=(),
                gate=True,
            )

        check(good)
        for name, bad in {
            "an undeclared extra token": good.replace("-q ", "-q -x ", 1),
            "a silently missing token": good.replace(" --disable-warnings", "", 1),
            "a second added -p": good.replace("-p tripwires", "-p tripwires -p extra", 1),
            # the same tokens, only the order differs: the tripwire is no longer the first -p
            "the tripwire not first": good.replace(
                "-p tripwires -p reportlog", "-p reportlog -p tripwires", 1
            ),
        }.items():
            assert bad != good, name
            with pytest.raises(AssertionError):
                check(bad)
        # a control changes exactly its declared tokens
        dropped = exact_scratch.command(node, drop=["--tb=no"])
        with pytest.raises(AssertionError):
            check(dropped)
        check(dropped, drop=["--tb=no"])

    @needs_bash
    def test_a_positive_control_is_never_candidate_evidence(self, exact_scratch: Exact) -> None:
        exact_scratch.module(
            "pytestmark = pytest.mark.real_api\n"
            "import subprocess\n"
            "def test_x():\n"
            "    try:\n        subprocess.Popen(['x'])\n    except AssertionError:\n        pass\n"
        )
        ran = exact_scratch.run("test_surface.py::test_x", expect_hits=True, positive_control=True)
        assert ran.control and ran.saved == "" and not exact_scratch.evidence_file.exists()
        with pytest.raises(AssertionError, match="never classified"):
            ran.verdict  # noqa: B018 - the property raises
        assert "subprocess.Popen" in exact_scratch.sandbox.hits()

    def test_a_class_s_sandbox_never_installs_seams_or_the_git_replacement(
        self, scratch: Sandbox
    ) -> None:
        scratch.pytester.makeini(SANDBOX_INI)
        scratch.write(
            "test_x.py",
            "import pytest\npytestmark = pytest.mark.real_api\ndef test_x():\n    pass\n",
        )
        scratch.run("test_x.py", "-m", "real_api", gate=False)
        assert "seams" not in " ".join(scratch.last_argv)
        assert not (scratch.pytester.path / "seams.py").exists()
        with pytest.raises(AssertionError):
            scratch.conftest()  # the repository conftest is Class R only
        with pytest.raises(AssertionError):
            scratch.live_tests()

    def test_a_class_r_sandbox_installs_the_seam_recorders(self, sandbox: Sandbox) -> None:
        assert (sandbox.pytester.path / "seams.py").exists()
        sandbox.live_tests()  # only a Class R sandbox collects the real live tests

    def test_a_class_s_file_that_imports_a_provider_fails_the_builder_audit(
        self, scratch: Sandbox
    ) -> None:
        for source in (
            "from conductor.providers import claude_agent_sdk\n",
            "import claude_agent_sdk\n",
            "from tests.test_integration import test_claude_agent_sdk_subscription_real\n",
            "x = 'live_module_under_test'\n",
        ):
            with pytest.raises(AssertionError):
                scratch.write("bad.py", source)


# ============================================================================
# H41: hermeticity audit of the builder
# ============================================================================

SCRATCH_SOURCES = {
    "INHERIT_TEST": INHERIT_TEST,
    "EXTERNAL_PLUGIN": EXTERNAL_PLUGIN,
    "STDERR_PLUGIN": STDERR_PLUGIN,
    "REPLAY_PLUGIN": REPLAY_PLUGIN,
    "FAILING_CONFTEST": FAILING_CONFTEST,
    "FAILING_PLUGIN": FAILING_PLUGIN,
    "LAYER1_CONTROL": LAYER1_CONTROL,
    "SENTINEL_CONTROL": SENTINEL_CONTROL,
    "REPORT_LOG_PLUGIN": REPORT_LOG_PLUGIN,
    "IMPORT_TIME_ATTEMPT": IMPORT_TIME_ATTEMPT,
}

# The class every sandbox-using test class belongs to (design section 10).
SANDBOX_CLASS = {
    "TestSandboxGates": "R",
    "TestSandboxIsolation": "R",
    "TestSandboxPrerequisites": "R",
    "TestZeroSkipSandbox": "R",
    "TestOutputSurface": "R",
    "TestOutputMatrix": "R",
    "TestReportSanitizer": "R",
    "TestInterruptSanitizer": "R",
    "TestExceptionRendering": "R",
    "TestWarnings": "R",
    "TestFallbackEvidence": "R",
    "TestRunLevelEvidence": "R",
    "TestRegistrationBoundaries": "R",
    "TestEndToEnd": "R",
    "TestCollectionMatrix": "S",
    "TestPreReporterFailures": "S",
    "TestInheritedConfiguration": "S",
    "TestInheritedPythonColourAndEntryPoints": "S",
    "TestScratchReplay": "S",
    "TestIsolationControls": "S",
    "TestBuilderAudit": "S",
    "TestClassifierEntryPoint": "C",
    "TestClassifierStartup": "C",
    "TestShellGate": "C",
}
FIXTURE_CLASS = {
    "sandbox": "R",
    "exact": "R",
    "scratch": "S",
    "exact_scratch": "S",
    "class_c": "C",
    "gate": "C",
}


class TestBuilderAudit:
    """H41: AST and text checks over the builder and every class of sandbox test."""

    def test_every_scratch_source_imports_nothing_from_the_live_code(self) -> None:
        for name, source in SCRATCH_SOURCES.items():
            assert scratch_import_problems(source) == [], name

    def test_layer_one_is_stdlib_only_and_first_and_layer_two_is_class_r_only(self) -> None:
        tree = ast.parse(LAYER1_PLUGIN)
        roots: set[str] = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                roots.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom):
                roots.add((n.module or "").split(".")[0])
        assert roots <= {"asyncio", "os", "socket", "subprocess", "sys"}, roots
        assert "_arm_all()  # at import" in LAYER1_PLUGIN  # armed at import, not at session start
        source = inspect.getsource(Sandbox)
        run_source = inspect.getsource(Sandbox.run)
        assert run_source.index('"tripwires"') < run_source.index(
            '"seams"'
        )  # the tripwire is first
        assert 'if klass == "R":\n            pytester.makepyfile(seams=SEAM_PLUGIN)' in source
        assert "conductor" not in LAYER1_PLUGIN.replace('"conductor")', "")  # only an audit name

    def test_the_zero_hit_assertion_audit_and_isolation_live_in_the_builder(self) -> None:
        run_source = inspect.getsource(Sandbox.run)
        assert "assert_clean_run" in run_source and "child_environment" in run_source
        assert "assert_isolated" in inspect.getsource(Sandbox.child_environment)
        assert "modules_audit" in inspect.getsource(Sandbox.assert_clean_run)
        assert "assert_clean_run" in inspect.getsource(Exact.run)
        assert "hits() == []" in inspect.getsource(Sandbox.assert_clean_run).replace(
            " ", ""
        ) or "self.hits() == []" in inspect.getsource(Sandbox.assert_clean_run)

    def test_the_marker_is_registered_and_the_selection_is_unique(self) -> None:
        assert "real_api:" in SANDBOX_INI
        assert 'if self.sandbox.klass == "S":' in inspect.getsource(Exact.run)
        assert "S3" in inspect.getsource(Exact.run) and "R4" in inspect.getsource(Exact.run)

    def test_the_sandbox_rootdir_and_pythonpath_exclude_the_repository_in_class_s(
        self, scratch: Sandbox
    ) -> None:
        env = scratch.child_environment()
        assert "PYTHONPATH" not in env  # a Class S child never sees the repository src or tests
        for value in env.values():
            assert str(REPO_ROOT) not in value

    def test_every_sandbox_test_declares_its_class(self) -> None:
        tree = ast.parse(Path(__file__).read_text())
        found: dict[str, set[str]] = {}
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or not node.name.startswith("Test"):
                continue
            used = {
                FIXTURE_CLASS[a.arg]
                for fn in node.body
                if isinstance(fn, ast.FunctionDef)
                for a in fn.args.args
                if a.arg in FIXTURE_CLASS
            }
            if used:
                found[node.name] = used
        for name, classes in found.items():
            assert name in SANDBOX_CLASS, f"{name} does not declare its sandbox class"
            declared = SANDBOX_CLASS[name]
            assert classes <= {declared, "R", "S", "C"} and (declared in classes or classes), name
        for name in SANDBOX_CLASS:
            assert any(isinstance(n, ast.ClassDef) and n.name == name for n in tree.body), name

    def test_class_r_tests_run_over_complete_fakes_and_a_replaced_git_seam(self) -> None:
        assert "configured_adapters" in FAKE_WORLD and "read_git_state" in GIT_SEAM_CONFTEST
        assert "__globals__" in GIT_SEAM_CONFTEST  # the module object the functions really use
        assert "import_module" not in GIT_SEAM_CONFTEST  # not a second import of the module


# ============================================================================
# H37: runbook discard, candidate, operator-sequence and interrupt statements
# ============================================================================


class TestRunbookStatements:
    """H37: a pure-text test over the runbook (no sandbox, no subprocess)."""

    TEXT = normalized(RUNBOOK_PATH.read_text())

    @pytest.mark.parametrize(
        "statement",
        [
            "must **not be shared, committed, quoted as evidence or used to authorize the next "
            "live step**",
            "necessary, never sufficient",
            "`-I -S -B`",
            "PIPELINE_STATUS=$?",
            "the **pipeline status under `pipefail`, not necessarily pytest's own status**",
            "tests **both** the exit status and the exact stdout token",
            "**kept** locally",
            "leaves **no valid capture**",
            "**Bash or Zsh**",
            "**not** generic POSIX `sh`",
            "**plain terminal session**",
            "are **not accepted** as part of the evidence environment",
            "`conftest` import failure or a plugin-load failure",
            "`prereq_terminalreporter_missing`",
            "failure to register the evidence plugin",
            "registration window",
            "exactly three lines",
            "`(to show a full traceback on KeyboardInterrupt use --full-trace)`",
            "`--color=no`",
            "`PYTEST_DISABLE_PLUGIN_AUTOLOAD` is deliberately **not**",
            "rerun the offline safety tests before any live validation",
            "the script exits with status 3, so a caller can never mistake it for success",
        ],
    )
    def test_the_statement_is_present(self, statement: str) -> None:
        assert normalized(statement) in self.TEXT, statement

    def test_the_guarantee_is_restricted_to_a_validated_capture_and_not_overclaimed(self) -> None:
        text = self.TEXT
        assert (
            "applies to a capture the classifier prints `official` or `readiness_only` for" in text
        )
        assert "absolute paths can be written transiently by a failed run" in text
        for overclaim in (
            "paths are never written",
            "reaching the gate fixture guarantees",
            "only framework lines reach",
            "judged by eye is enough",
        ):
            assert overclaim not in text, overclaim

    def test_a_failure_record_is_never_evidence_and_readiness_only_is_not_official(self) -> None:
        text = self.TEXT
        assert "never** shared, committed, quoted as successful evidence" in text
        assert "not official end-to-end evidence" in text
        assert "No live validation has been run yet" in text

    def test_the_changelog_describes_a_harness_not_a_validation_that_ran(self) -> None:
        fragment = REPO_ROOT / "changelog.d" / "+claude-agent-sdk-subscription-validation.added.md"
        text = fragment.read_text()
        assert len(text.strip().splitlines()) == 1  # one concise entry
        assert text.startswith("Opt-in live-validation harness and operator runbook")
        assert "Opt-in live validation" not in text

    def test_the_readiness_and_live_operations_each_have_their_own_script(self) -> None:
        assert "its own script invocation" in self.TEXT
        assert lm.MATRIX_BLOCK.count("exit 0 ;;") == 1  # only the expected-token candidate
        assert lm.MATRIX_BLOCK.count("exit 3 ;;") == 1  # a retained failure record is not success
        assert "exit 1 ;;" in lm.MATRIX_BLOCK  # explicit termination, not falling off the end
