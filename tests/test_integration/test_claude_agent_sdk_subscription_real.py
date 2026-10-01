"""Opt-in real-subscription validation harness for the Claude Agent SDK provider.

This module is doubly gated and fail-closed:

* Both gates must be supplied to the *same* command: ``-m real_api`` **and**
  ``CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION=1`` (exact value).  The variable is a command
  prefix, never exported, never set in CI, a shell profile or an IDE run configuration.
* Once both gates are active, an unmet prerequisite is a **failure**, never a skip.
  ``pytest.skip`` is never used for an unexecuted later case.
* Every helper and adapter that could reach readiness, the SDK, the CLI or the network
  enforces the gate *and* the isolation prerequisite itself, as its first two statements.

The module has four layers:

* **Classifier head** -- the closed output grammar, the evidence allowlist and validators, the
  ``Outcome`` enum, ``scan_is_clean_and_complete`` and ``classify_capture``, defined *above every
  other import* with the standard library only (``re``, ``json``, ``sys``, ``enum``, ``typing``,
  ``collections.abc``).  Run as a script it is the operator's capture classifier (below).
* **Pure / hermetic layer** -- gates, isolation, source tree, canaries, model, quota,
  process-table parsing, the L3 classifier, the passive observer, the ordered state machine, the
  case success predicates, the report sanitizer and the evidence plugin.
* **Adapter seams** -- ``ReadinessAdapter``, ``WorkflowExecutionAdapter``,
  ``CliEvidenceAdapter``, ``DescendantSnapshotAdapter`` and ``ObserverInstaller`` protocols.
* **Real adapters** -- ``Real*Adapter`` classes behind ``configured_adapters()``: the provider
  factory and real readiness for L0; ``load_config`` -> ``ProviderRegistry`` ->
  ``WorkflowEngine`` -> ``display_usage_summary`` for L1 / L3 / L2; the passive spy on the real
  ``ClaudeSDKClient.receive_response``; the guarded process-table snapshot; the CLI evidence.

Everything except the two gated live tests at the bottom is exercised offline by
``tests/test_config/test_claude_subscription_real_gate.py`` with every CLI, SDK-transport,
process and network boundary replaced.  Nothing here has been run against a real login.

What a live run may consume: at most three potentially quota-consuming attempts (L1, L3, L2),
enforced by ``QuotaCounter``.  In the current production path the readiness probe
(``claude auth status --json``) runs once for L0 and twice for each of L1 and L2.

Retained output.  Only :func:`evidence` records are ever retained, as ``EVIDENCE {json}`` lines
written by the terminal-summary hook of the evidence plugin: one session-facts record (the
official path only), one per-case record per case that ran, and exactly one run-level record
(Path A: ``run_level_record`` after ``run_session``; Path B: ``fail_closed(exc, config)`` for a
failure that escapes before ``run_session`` returns; never both).  Every case scans eight fixed
streams for the canary (:data:`REQUIRED_STREAMS`) and reports ``canary_scan`` as eight fixed
``<stream>:<clean|leak|not_available>`` strings.  SDK and provider log records are captured by a
private handler (:class:`PrivateLogCapture`) that never reaches pytest's report handlers.

The authorized commands (:data:`READINESS_ONLY_COMMAND`, :data:`OFFICIAL_COMMAND`) start with the
seven-variable ``env -u`` prefix, carry ``-q --color=no --show-capture=no --disable-warnings
--tb=no -rN -p no:cacheprovider`` and never ``-rA`` or ``-s``, and write through
``2>&1 | tee`` under ``pipefail``.  ``PYTEST_DISABLE_PLUGIN_AUTOLOAD`` is deliberately not
set.  Under both gates a :class:`ReportSanitizer` renders every failure and interrupt from fixed
text.

Registration order inside the session fixture (normative): both gates, the inert terminal-reporter
lookup, the evidence plugin, the report sanitizer (the very next statement), then every other
prerequisite.  Two boundaries this order does not close are documented, not hidden: a failure
while registering the evidence plugin leaves no evidence section, and a failure or interrupt in
the registration window between the evidence plugin and the sanitizer leaves a section
followed by pytest's default rendering.  Neither the fixture nor the flags guarantee anything
about every line of a capture; the only guarantee is the verdict of the classifier below.

The capture classifier.  ``"$PY" -I -S -B <this module> --check-capture <file> --pipeline-status
<N>`` prints exactly one of ``official`` (exit 0), ``readiness_only`` (exit 0), ``failure_record``
(exit 3) or ``discard <code>`` (exit 1), reads only the named file, needs no gate and no
environment variable, imports nothing beyond the head, echoes nothing and deletes nothing.
``<N>`` is the pipeline status under ``pipefail``, which is not necessarily pytest's own status.
The operator's shell gate around it (:data:`PRE_GATE`, :data:`CLASSIFY_BLOCK`,
:data:`MATRIX_BLOCK`) tests both the exit status and the exact token and deletes the capture on
every other combination.  An interruption before a run-level record exists is discarded as
``run_record_missing``.  A terminal width beyond the grammar's bounds (a ``COLUMNS`` far above
500) fails closed.  ``pytest`` is lower-bounded and not upper-pinned and the interrupt hint and
the count lines are pytest constants: a change to any fixed line makes the classifier discard the
capture, and the offline gate tests are rerun after any pytest upgrade and before live validation.

Cancellation.  ``KeyboardInterrupt``, ``asyncio.CancelledError`` and any other non-``Exception``
``BaseException`` are never converted: scan, descendant observation and cleanup run, findings are
recorded as secondary evidence, and the original exception object is re-raised unchanged.  Only
the terminal rendering of the cancellation is sanitized.
"""

from __future__ import annotations

import enum
import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Final, cast

# ============================================================================
# Classifier head: standard library only, above every other import
# ============================================================================
#
# The head must precede every other import (it exits before them in classifier mode), so the
# ordinary imports that follow it are deliberately not at the top of the file:
#
# ruff: noqa: E402
#
# From here to the dispatch at the end of this block the module imports only ``re``, ``json``,
# ``sys``, ``enum``, ``typing`` and ``collections.abc`` (a pinned set; a static AST test and an
# import audit prove it).  Run as a script,
#
#     "$PY" -I -S -B <this module> --check-capture <file> --pipeline-status <N>
#
# classifies a saved capture and exits *here*, before ``pytest``, ``conductor``, the SDK, any
# authentication code, ``subprocess``, ``asyncio`` or any networking module is imported.  The
# grammar, the evidence allowlist and the validators are defined once, in this block, and are
# shared by the evidence emitter and the capture classifier.

# ============================================================================
# Fixed outcomes
# ============================================================================


class Outcome(enum.StrEnum):
    """Every fixed enum a case, session or evidence record may carry."""

    OK = "ok"
    LIVE_OPT_IN_ERROR = "live_opt_in_error"
    # Prerequisite / safety failures.
    ISOLATION_FIXTURES_MISSING = "isolation_fixtures_missing"
    PREREQ_SDK_MISSING = "prereq_sdk_missing"
    PREREQ_CLI_MISSING = "prereq_cli_missing"
    PREREQ_CLI_NOT_BUNDLED = "prereq_cli_not_bundled"
    SOURCE_TREE_MISMATCH = "source_tree_mismatch"
    READINESS_STUB_ACTIVE = "readiness_stub_active"
    PREREQ_PS_MISSING = "prereq_ps_missing"
    PREREQ_TERMINALREPORTER_MISSING = "prereq_terminalreporter_missing"
    PREREQ_REPORT_SANITIZER_UNAVAILABLE = "prereq_report_sanitizer_unavailable"
    PREREQ_FILE_CONSOLE_ACTIVE = "prereq_file_console_active"
    INVALID_MODEL_OVERRIDE = "invalid_model_override"
    DESCENDANT_LEAK = "descendant_leak"
    CANARY_LEAK = "canary_leak"
    CANARY_SCAN_INCOMPLETE = "canary_scan_incomplete"
    L2_L3_NOT_PAIRED = "l2_l3_not_paired"
    QUOTA_CEILING_EXCEEDED = "quota_ceiling_exceeded"
    ADAPTERS_NOT_WIRED = "adapters_not_wired"
    # Case-level failures.
    NOT_LOGGED_IN = "not_logged_in"
    UNPRICED_MODEL_LABEL_UNEXERCISED = "unpriced_model_label_unexercised"
    EFFECTIVE_MODEL_MISSING = "effective_model_missing"
    CASE_FAILED = "case_failed"
    INTERRUPTED = "interrupted"
    # Case success predicates.
    READINESS_EVIDENCE_MISSING = "readiness_evidence_missing"
    READINESS_EVIDENCE_CONTRADICTION = "readiness_evidence_contradiction"
    FIRST_PARTY_MISMATCH = "first_party_mismatch"
    BILLING_NOT_SUBSCRIPTION = "billing_not_subscription"
    BILLING_AGGREGATE_MISMATCH = "billing_aggregate_mismatch"
    BILLING_LABEL_MISSING = "billing_label_missing"
    OUTPUT_MISSING = "output_missing"
    CANARY_USED_IN_L2 = "canary_used_in_l2"
    # L3 classifier results.
    INVALID_KEY = "invalid_key"
    FELL_BACK_TO_LOGIN = "fell_back_to_login"
    MODEL_UNAVAILABLE = "model_unavailable"
    INCONCLUSIVE = "inconclusive"
    # Descendant verdicts.
    NO_DESCENDANTS_REMAINING = "no_descendants_remaining"
    # Evidence data (never skips).
    NOT_EXECUTED_AFTER_SAFETY_FAILURE = "not_executed_after_safety_failure"
    NOT_EXECUTED_AFTER_L0_FAILURE = "not_executed_after_l0_failure"
    NOT_EXECUTED_AFTER_L1_FAILURE = "not_executed_after_l1_failure"
    NOT_EXECUTED_L3_FELL_BACK_TO_LOGIN = "not_executed_l3_fell_back_to_login"
    NOT_EXECUTED_L3_INCONCLUSIVE = "not_executed_l3_inconclusive"
    NOT_EXECUTED_L3_MODEL_UNAVAILABLE = "not_executed_l3_model_unavailable"
    NOT_EXECUTED_AFTER_INTERRUPT = "not_executed_after_interrupt"


_OUTCOME_VALUES: Final = frozenset(o.value for o in Outcome)
NOT_EXECUTED_VALUES: Final = frozenset(v for v in _OUTCOME_VALUES if v.startswith("not_executed_"))

# ============================================================================
# Evidence contract: allowlist and validators (shared by the emitter and the classifier)
# ============================================================================

# The eight streams scanned for the canary, in the order ``canary_scan`` reports them.
REQUIRED_STREAMS: Final = (
    "stdout_stderr",
    "console",
    "logs",
    "exceptions",
    "events",
    "workflow_result",
    "evidence",
    "tmp_files",
)
SCAN_STATES: Final = ("clean", "leak", "not_available")
INTERRUPT_KINDS: Final = ("none", "keyboard_interrupt", "cancelled", "other_base_exception")
SECONDARY_FINDINGS: Final = ("canary_leak", "descendant_leak")
CLEANUP_STEPS: Final = ("descendants", "evidence")
CASE_NAMES: Final = ("L0", "L1", "L3", "L2")
_REAL_CASES: Final = frozenset(CASE_NAMES)
UNAVAILABLE: Final = "unavailable"
MAX_PLUGINS: Final = 32

_SHORT_RE: Final = re.compile(r"[A-Za-z0-9._+:=,@-]{1,120}")
_ENV_NAME_RE: Final = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
_PS_NAME_RE: Final = re.compile(r"[A-Za-z0-9._+?-]{1,32}")
_IDENT_RE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}", re.ASCII)
UNKNOWN_EXCEPTION: Final = "unknown_exception"
_CLI_VERSION_RE: Final = re.compile(r"[0-9A-Za-z.+_-]{1,40}")
_MODEL_RE: Final = re.compile(r"claude-[a-z0-9][a-z0-9.@-]{0,60}")
_GIT_SHA_RE: Final = re.compile(r"[0-9a-f]{40}")
_PYTEST_VERSION_RE: Final = re.compile(
    r"[0-9]{1,3}(?:\.[0-9]{1,4}){1,3}(?:(?:a|b|rc)[0-9]{1,3})?(?:\.(?:dev|post)[0-9]{1,4})?",
    re.ASCII,
)
_PLUGIN_RE: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}==[0-9A-Za-z][0-9A-Za-z.+!_-]{0,31}", re.ASCII
)
_CLI_CLASSES: Final = frozenset({"bundled", "path", "fallback"})
_CASE_NAMES: Final = frozenset({*CASE_NAMES, "session"})
_BILLING_MODES: Final = frozenset({"subscription", "metered_api", "unknown"})
_FIRST_PARTY: Final = frozenset({"validated", "unexercised", "mismatch"})
_PREFIXES: Final = ("session", *CASE_NAMES)


class EvidenceError(ValueError):
    """An evidence field was rejected.  The message never contains the value."""


def _is_bool(v: object) -> bool:
    return isinstance(v, bool)


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_float(v: object) -> bool:
    # ``v - v == 0`` is false for NaN and both infinities (and true for every finite number).
    return isinstance(v, int | float) and not isinstance(v, bool) and v - v == 0


def _is_short(v: object) -> bool:
    return isinstance(v, str) and _SHORT_RE.fullmatch(v) is not None


def _is_outcome(v: object) -> bool:
    if isinstance(v, Outcome):
        return True
    return isinstance(v, str) and v in _OUTCOME_VALUES


def _is_env_list(v: object) -> bool:
    return (
        isinstance(v, list)
        and len(v) <= 64
        and all(isinstance(n, str) and _ENV_NAME_RE.fullmatch(n) for n in v)
    )


def _is_pid_row(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and set(row) == {"pid", "name"}
        and _is_int(row["pid"])
        and isinstance(row["name"], str)
        and _PS_NAME_RE.fullmatch(row["name"]) is not None
    )


def _is_pid_list(v: object) -> bool:
    return isinstance(v, list) and len(v) <= 256 and all(_is_pid_row(row) for row in v)


def _is_canary_scan(v: object) -> bool:
    """Exactly eight fixed ``<stream>:<state>`` strings, in :data:`REQUIRED_STREAMS` order."""
    return (
        isinstance(v, list)
        and len(v) == len(REQUIRED_STREAMS)
        and all(
            isinstance(entry, str) and entry.split(":", 1)[0] == name and _scan_state(entry)
            for entry, name in zip(v, REQUIRED_STREAMS, strict=True)
        )
    )


def _scan_state(entry: str) -> bool:
    parts = entry.split(":")
    return len(parts) == 2 and parts[1] in SCAN_STATES


def _is_cleanup_failed(v: object) -> bool:
    """A non-empty, duplicate-free list of fixed cleanup steps, in cleanup order."""
    return (
        isinstance(v, list)
        and 0 < len(v) <= len(CLEANUP_STEPS)
        and all(isinstance(step, str) for step in v)
        and v == [step for step in CLEANUP_STEPS if step in v]
    )


def ordered_cleanup(steps: Iterable[str]) -> list[str]:
    """``steps`` as the fixed enum, each once, in cleanup order (anything else is dropped)."""
    wanted = set(steps)
    return [step for step in CLEANUP_STEPS if step in wanted]


def exception_class_of(exc: object) -> str:
    """The class name of ``exc`` if it is a short ASCII identifier, else ``unknown_exception``."""
    try:
        name = type(exc).__name__
    except Exception:
        return UNKNOWN_EXCEPTION
    if isinstance(name, str) and _IDENT_RE.fullmatch(name):
        return name
    return UNKNOWN_EXCEPTION


def parse_primary_failure(value: object) -> tuple[str, str, str] | None:
    """``(prefix, enum, class)`` of ``<prefix>:<enum>:<Class>``, or ``None`` if not that form.

    The prefix is ``session`` (no case wrapper was active) or a case; the class may be ``none``.
    """
    if not isinstance(value, str):
        return None
    parts = value.split(":")
    if len(parts) != 3:
        return None
    prefix, enum_value, cls = parts
    if prefix not in _PREFIXES or enum_value not in _OUTCOME_VALUES:
        return None
    if _IDENT_RE.fullmatch(cls) is None:
        return None
    return prefix, enum_value, cls


def parse_not_executed(value: object) -> list[tuple[str, str]] | None:
    """``[(case, value), ...]`` of ``"<case>:<value>,<case>:<value>"``: case order, no duplicate."""
    if not isinstance(value, str) or not value:
        return None
    entries: list[tuple[str, str]] = []
    last = -1
    for item in value.split(","):
        case, sep, state = item.partition(":")
        if not sep or case not in CASE_NAMES or state not in NOT_EXECUTED_VALUES:
            return None
        index = CASE_NAMES.index(case)
        if index <= last:
            return None
        last = index
        entries.append((case, state))
    return entries


def _is_primary_failure(v: object) -> bool:
    return parse_primary_failure(v) is not None


def _is_not_executed(v: object) -> bool:
    return parse_not_executed(v) is not None


def _is_pytest_version(v: object) -> bool:
    return isinstance(v, str) and (v == UNAVAILABLE or _PYTEST_VERSION_RE.fullmatch(v) is not None)


def _is_plugins(v: object) -> bool:
    """Sorted, duplicate-free ``name==version`` entries (at most 32), or exactly ``unavailable``."""
    if not isinstance(v, list):
        return False
    if v == [UNAVAILABLE]:
        return True
    return (
        len(v) <= MAX_PLUGINS
        and all(isinstance(entry, str) and _PLUGIN_RE.fullmatch(entry) for entry in v)
        and v == sorted(set(cast("list[str]", v)))
    )


def _subset_list(allowed: Sequence[str], limit: int) -> Callable[[object], bool]:
    """A duplicate-free list of at most ``limit`` members of the fixed set ``allowed``."""
    return lambda v: (
        isinstance(v, list)
        and len(v) <= limit
        and len(set(v)) == len(v)
        and all(isinstance(item, str) and item in allowed for item in v)
    )


def _matcher(pattern: re.Pattern[str]) -> Callable[[object], bool]:
    return lambda v: isinstance(v, str) and pattern.fullmatch(v) is not None


def _member_of(values: frozenset[str]) -> Callable[[object], bool]:
    return lambda v: isinstance(v, str) and v in values


# ``official``, ``skipped_reports`` and ``zero_skip_verdict`` are deliberately *not* keys: they are
# the three G4 section lines written by the evidence plugin, the only place they appear.
_EVIDENCE_SPECS: Final[dict[str, Callable[[object], bool]]] = {
    "date_utc": _is_short,
    "host_os": _is_short,
    "python_version": _is_short,
    "git_sha": _matcher(_GIT_SHA_RE),
    "git_dirty": _is_bool,
    "source_tree_verdict": _is_short,
    "isolation_verdict": _is_short,
    "sdk_version": _is_short,
    "cli_class": _member_of(_CLI_CLASSES),
    "cli_version": _matcher(_CLI_VERSION_RE),
    "requested_model": _matcher(_MODEL_RE),
    "effective_model": _matcher(_MODEL_RE),
    "case": _member_of(_CASE_NAMES),
    "env_names_set": _is_env_list,
    "env_names_removed": _is_env_list,
    "ready": _is_bool,
    "auth_method_present": _is_bool,
    "api_provider_present": _is_bool,
    "api_provider_is_first_party": _is_bool,
    "subscription_type_present": _is_bool,
    "api_key_source_present": _is_bool,
    "billing_mode": _member_of(_BILLING_MODES),
    "billing_reason": _is_short,
    "billing_state": _is_short,
    "first_party_constant": _member_of(_FIRST_PARTY),
    "outcome": _is_outcome,
    "adapter_outcome": _is_outcome,
    "secondary_findings": _subset_list(SECONDARY_FINDINGS, len(SECONDARY_FINDINGS)),
    "interrupted": _member_of(frozenset(INTERRUPT_KINDS)),
    "cleanup_failed": _is_cleanup_failed,
    "billing_label_seen": _is_bool,
    "attempted_quota_execution": _is_bool,
    "elapsed_s": _is_float,
    "input_tokens": _is_int,
    "output_tokens": _is_int,
    "est_cost_usd": _is_float,
    "descendants": _is_outcome,
    "descendant_report": _is_pid_list,
    "canary_scan": _is_canary_scan,
    "passed": _is_int,
    "failed": _is_int,
    "quota_attempts_total": _is_int,
    "quota_ceiling": _is_int,
    "not_executed": _is_not_executed,
    "primary_failure": _is_primary_failure,
    "pytest_version": _is_pytest_version,
    "plugins": _is_plugins,
    "exception_class": _matcher(_IDENT_RE),
}
EVIDENCE_KEYS: Final = frozenset(_EVIDENCE_SPECS)

# The three record kinds (design section 9): the keys of each, fixed once.
SESSION_KEYS: Final = frozenset(
    {
        "case",
        "date_utc",
        "host_os",
        "python_version",
        "sdk_version",
        "git_sha",
        "git_dirty",
        "source_tree_verdict",
        "cli_class",
        "cli_version",
        "isolation_verdict",
    }
)
RUN_KEYS: Final = frozenset(
    {
        "passed",
        "failed",
        "quota_attempts_total",
        "quota_ceiling",
        "primary_failure",
        "not_executed",
        "pytest_version",
        "plugins",
    }
)
CASE_KEYS: Final = frozenset((EVIDENCE_KEYS - SESSION_KEYS - RUN_KEYS) | {"case"})


def validate_record(record: Mapping[str, object]) -> None:
    """Raise :class:`EvidenceError` (never echoing a value) unless every key/value is allowed."""
    for key, value in record.items():
        spec = _EVIDENCE_SPECS.get(key)
        if spec is None:
            raise EvidenceError("evidence key not allowed")
        if not spec(value):
            raise EvidenceError(f"evidence value rejected for {key}")
        if isinstance(value, str) and "sk-ant" in value:
            raise EvidenceError(f"evidence value rejected for {key}")


def evidence(**fields: object) -> dict[str, object]:
    """Build one sanitized evidence record.

    Fixed key allowlist; values restricted to bool/int/float, pattern-checked short strings,
    enum literals, lists of environment *names*, lists of ``{"pid", "name"}``, bounded lists
    drawn from fixed sets, or the eight fixed ``canary_scan`` strings.  Anything else raises
    :class:`EvidenceError` without echoing the value.  A per-case record must carry
    ``canary_scan``: a case that was never scanned cannot be reported.
    """
    validate_record(fields)
    record: dict[str, object] = {
        key: value.value if isinstance(value, Outcome) else value for key, value in fields.items()
    }
    if record.get("case") in _REAL_CASES and "canary_scan" not in record:
        raise EvidenceError("case record without canary_scan")
    return record


def emit_evidence(record: Mapping[str, object]) -> str:
    """The one line retained for a record: ``EVIDENCE {json}`` (re-validated)."""
    return "EVIDENCE " + json.dumps(evidence(**dict(record)), sort_keys=True)


def unavailable_allowed(case: object, stream: str) -> bool:
    """``not_available`` is permitted only for a missing result, and for L0's console/events."""
    return stream == "workflow_result" or (str(case) == "L0" and stream in ("console", "events"))


def scan_is_clean_and_complete(entries: object, case: object) -> bool:
    """A ``canary_scan`` with no leak and no ``not_available`` where it is not allowed."""
    if not _is_canary_scan(entries):
        return False
    for entry, name in zip(cast("list[str]", entries), REQUIRED_STREAMS, strict=True):
        state = entry.split(":", 1)[1]
        if state == "leak" or (state == "not_available" and not unavailable_allowed(case, name)):
            return False
    return True


# ============================================================================
# Capture classifier: closed grammar, record model and the four verdicts
# ============================================================================

VERDICT_OFFICIAL: Final = "official"
VERDICT_READINESS_ONLY: Final = "readiness_only"
VERDICT_FAILURE_RECORD: Final = "failure_record"
VERDICT_DISCARD: Final = "discard"
VERDICT_EXIT_STATUS: Final = {
    VERDICT_OFFICIAL: 0,
    VERDICT_READINESS_ONLY: 0,
    VERDICT_FAILURE_RECORD: 3,
    VERDICT_DISCARD: 1,
}
REASON_CODES: Final = (
    "capture_missing",
    "capture_unreadable",
    "capture_too_large",
    "capture_empty",
    "non_ascii_or_control",
    "no_evidence_section",
    "multiple_evidence_sections",
    "section_order_violation",
    "line_outside_grammar",
    "interrupt_grammar_violation",
    "evidence_json_malformed",
    "evidence_record_invalid",
    "run_record_missing",
    "run_record_duplicate",
    "evidence_inconsistent",
    "count_line_missing",
    "pipeline_status_invalid",
    "pipeline_status_nonzero",
    "usage_error",
    "internal_error",
)
MAX_CAPTURE_BYTES: Final = 1024 * 1024
CHECK_CAPTURE_OPTION: Final = "--check-capture"
PIPELINE_STATUS_OPTION: Final = "--pipeline-status"

# Literal bounded regexes: every quantifier is bounded and there is no ``.*``.
_DUR: Final = r"[0-9]{1,6}\.[0-9]{2}s(?: \([0-9]{1,3}:[0-9]{2}:[0-9]{2}\))?"
_PCT: Final = r"\[ {0,2}[0-9]{1,3}%\]"
_CNT: Final = r"[0-9]{1,9} (?:failed|passed|skipped|deselected|xfailed|xpassed|warnings?|errors?)"
_OUTCOME_RE: Final = r"[a-z][a-z0-9_]{0,63}"
_CLASS_RE: Final = r"[A-Za-z_][A-Za-z0-9_]{0,63}"
_CASE_RE: Final = r"L0|L1|L3|L2"
_LISTING: Final = rf"(?:{_CASE_RE}):{_OUTCOME_RE}(?:,(?:{_CASE_RE}):{_OUTCOME_RE}){{0,7}}"
# G1 (blank) is the empty string and is handled by equality.
GRAMMAR: Final[dict[str, str]] = {
    "G2": r"[.sFExX]{1,512}(?: {1,512}" + _PCT + r")?",
    "G3": r"={1,200} claude subscription live evidence ={1,200}",
    "G4a": r"skipped_reports: [0-9]{1,9}",
    "G4b": r"zero_skip_verdict: (?:pass|fail)",
    "G4c": r"official: (?:true|false)",
    "G5": r"EVIDENCE \{[\x20-\x7e]{0,16000}\}",
    "G6": r"evidence_fallback_failed: (?:L0|L1|L3|L2)",
    "G7a": r"!{1,200} KeyboardInterrupt !{1,200}",
    "G7b": r"interrupted: details withheld",
    "G7c": r"\(to show a full traceback on KeyboardInterrupt use --full-trace\)",
    "G8a": r"no tests ran in " + _DUR,
    "G8b": _CNT + r"(?:, " + _CNT + r"){0,7} in " + _DUR,
    "G8c": r"(?:!{1,200} )?Interrupted: [0-9]{1,9} errors? during collection(?: !{1,200})?",
    "G9a": r"unexpected exception(?:: " + _CLASS_RE + r")?",
    "G9b": r"harness failure",
    "G9c": _OUTCOME_RE + r":(?:HarnessFailure|LiveOptInError)",
    "G9d": (
        rf"cases: {_LISTING}; first_failure: (?:{_CASE_RE}|session|none):{_OUTCOME_RE}:"
        rf"(?:{_CLASS_RE}|none)(?:; also: {_LISTING})?"
    ),
}
_FORM_RES: Final = {name: re.compile(pattern, re.ASCII) for name, pattern in GRAMMAR.items()}
_FORMS_PRE_TAIL: Final = ("G1", "G9a", "G9b", "G9c", "G9d")
_COUNT_CATEGORIES: Final = (
    "failed",
    "passed",
    "skipped",
    "deselected",
    "xfailed",
    "xpassed",
    "warnings",
    "errors",
)
_COUNT_ENTRY_RE: Final = re.compile(
    r"([0-9]{1,9}) (failed|passed|skipped|deselected|xfailed|xpassed|warnings?|errors?)", re.ASCII
)
_COLLECTION_RE: Final = re.compile(
    r"Interrupted: ([0-9]{1,9}) (errors?) during collection", re.ASCII
)
_G9_OUTCOME_RE: Final = re.compile(
    r"(?<![A-Za-z0-9_])(?:L0|L1|L3|L2|session|none):([a-z][a-z0-9_]{0,63})", re.ASCII
)
_NON_PRINTABLE_RE: Final = re.compile(r"[^\x20-\x7e\n]")
_STATUS_RE: Final = re.compile(r"[0-9]{1,3}", re.ASCII)
_SESSION_ONLY: Final = frozenset(
    {
        Outcome.LIVE_OPT_IN_ERROR.value,
        Outcome.ISOLATION_FIXTURES_MISSING.value,
        Outcome.ADAPTERS_NOT_WIRED.value,
        Outcome.PREREQ_REPORT_SANITIZER_UNAVAILABLE.value,
        Outcome.PREREQ_FILE_CONSOLE_ACTIVE.value,
        Outcome.SOURCE_TREE_MISMATCH.value,
        Outcome.READINESS_STUB_ACTIVE.value,
        Outcome.PREREQ_CLI_MISSING.value,
        Outcome.PREREQ_CLI_NOT_BUNDLED.value,
        Outcome.PREREQ_SDK_MISSING.value,
        Outcome.PREREQ_PS_MISSING.value,
        Outcome.INVALID_MODEL_OVERRIDE.value,
    }
)
_CASE_LEVEL: Final = frozenset(
    {
        Outcome.NOT_LOGGED_IN.value,
        Outcome.UNPRICED_MODEL_LABEL_UNEXERCISED.value,
        Outcome.MODEL_UNAVAILABLE.value,
        Outcome.L2_L3_NOT_PAIRED.value,
        Outcome.QUOTA_CEILING_EXCEEDED.value,
    }
)
_OFFICIAL_OUTCOMES: Final = (
    Outcome.OK.value,
    Outcome.OK.value,
    Outcome.INVALID_KEY.value,
    Outcome.OK.value,
)
_QUOTA_ATTEMPT_LIMIT: Final = 3


def _canonical(number: str, *, minimum: int) -> int | None:
    """``int(number)`` unless it has a leading zero or is below ``minimum``."""
    if len(number) > 1 and number.startswith("0"):
        return None
    value = int(number)
    return value if value >= minimum else None


def _count_entries(line: str) -> dict[str, int] | None:
    """Categories of a G8b line, or ``None`` if the semantic rules are broken.

    Canonical order, each category at most once, every number at least 1 without a leading zero,
    and ``warning``/``error`` exactly when the number is 1.
    """
    body = line.rsplit(" in ", 1)[0]
    counts: dict[str, int] = {}
    last = -1
    for entry in body.split(", "):
        found = _COUNT_ENTRY_RE.fullmatch(entry)
        if found is None:
            return None
        number = _canonical(found.group(1), minimum=1)
        noun = found.group(2)
        if number is None:
            return None
        key = noun if noun in _COUNT_CATEGORIES else noun + "s"
        if key not in _COUNT_CATEGORIES:
            return None
        if key in ("warnings", "errors") and (noun == key) == (number == 1):
            return None  # singular exactly when the number is 1
        index = _COUNT_CATEGORIES.index(key)
        if index <= last:
            return None
        last = index
        counts[key] = number
    return counts


def _form_of(line: str) -> str | None:
    """The one grammar form ``line`` fully matches (semantic checks included), else ``None``."""
    if line == "":
        return "G1"
    for name, pattern in _FORM_RES.items():
        if pattern.fullmatch(line) is None:
            continue
        if name == "G4a" and _canonical(line.rsplit(" ", 1)[1], minimum=0) is None:
            return None
        if name == "G8b" and _count_entries(line) is None:
            return None
        if name == "G8c":
            collected = _COLLECTION_RE.search(line)
            if collected is None:
                return None
            number = _canonical(collected.group(1), minimum=1)
            if number is None or (collected.group(2) == "error") != (number == 1):
                return None
        if name == "G9c" and line.split(":", 1)[0] not in _OUTCOME_VALUES:
            return None
        if name == "G9d" and any(
            outcome not in _OUTCOME_VALUES for outcome in _G9_OUTCOME_RE.findall(line)
        ):
            return None
        return name
    return None


def _discard(code: str) -> tuple[str, str]:
    return VERDICT_DISCARD, code


def _looks_like_interrupt(line: str) -> bool:
    return "KeyboardInterrupt" in line or line.startswith("interrupted:")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _reject_constant(name: str) -> object:
    raise ValueError("non-finite number")


def _parse_record_line(line: str) -> dict[str, object] | None:
    """One strict JSON object, or ``None`` (malformed, duplicate key, ``NaN``, not an object)."""
    try:
        value = json.loads(
            line[len("EVIDENCE ") :],
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except Exception:  # ValueError, RecursionError: anything unparsable is malformed
        return None
    return value if isinstance(value, dict) else None


def _safe_case_record(record: Mapping[str, object]) -> bool:
    """Item 6 of the official and readiness contracts: nothing unsafe was found in the case."""
    return (
        not record.get("secondary_findings")
        and "cleanup_failed" not in record
        and record.get("interrupted") == "none"
        and record.get("descendants") == Outcome.NO_DESCENDANTS_REMAINING.value
        and scan_is_clean_and_complete(record.get("canary_scan"), record.get("case"))
    )


def _success_count(counts: Mapping[str, int] | None) -> bool:
    """``passed`` is exactly 1; only ``deselected`` and warnings may accompany it."""
    return (
        counts is not None
        and counts.get("passed") == 1
        and set(counts) <= {"passed", "deselected", "warnings"}
    )


def _check_record_kinds(
    records: list[dict[str, object]],
) -> tuple[dict[str, object] | None, list[dict[str, object]], dict[str, object] | None, str | None]:
    """Sort the records into the three kinds; ``(session, per_case, run, error_code)``."""
    sessions = [r for r in records if r.get("case") == "session"]
    cases = [r for r in records if r.get("case") in _REAL_CASES]
    runs = [r for r in records if "case" not in r]
    if not runs:
        return None, [], None, "run_record_missing"
    if len(runs) > 1:
        return None, [], None, "run_record_duplicate"
    if records[-1] is not runs[0] or len(sessions) > 1:
        return None, [], None, "evidence_inconsistent"
    if sessions and records[0] is not sessions[0]:
        return None, [], None, "evidence_inconsistent"
    order = [CASE_NAMES.index(str(r["case"])) for r in cases]
    if order != sorted(set(order)):
        return None, [], None, "evidence_inconsistent"
    return (sessions[0] if sessions else None), cases, runs[0], None


def _check_shape(
    session: dict[str, object] | None,
    cases: list[dict[str, object]],
    run: dict[str, object],
) -> bool:
    """Run shapes P, O and R of the prefix rule (design section 9), enum placement included."""
    case_names = [str(r["case"]) for r in cases]
    primary = parse_primary_failure(run["primary_failure"]) if "primary_failure" in run else None
    if primary is not None and primary[1] == Outcome.OK.value:
        return False  # a completed ``ok`` case is never the primary failure
    executed = parse_not_executed(run["not_executed"]) if "not_executed" in run else None
    listed = [case for case, _ in executed] if executed is not None else []
    if session is not None:  # shape O
        if primary is None:
            if case_names != list(CASE_NAMES) or listed:
                return False
        else:
            prefix = primary[0]
            if prefix == "session" or prefix not in case_names:
                return False
            if listed != [c for c in CASE_NAMES if c not in case_names]:
                return False
            record = next(r for r in cases if r["case"] == prefix)
            if record.get("outcome") != primary[1]:
                return False
    elif not cases:  # shape P
        if primary is None or primary[0] != "session":
            return False
        if listed not in (["L0"], list(CASE_NAMES)):
            return False
    elif case_names == ["L0"]:  # shape R
        if listed or (primary is not None and primary[0] != "L0"):
            return False
        if primary is not None and cases[0].get("outcome") != primary[1]:
            return False
    else:
        return False
    if primary is not None:
        prefix, enum_value, _cls = primary
        if enum_value == Outcome.PREREQ_TERMINALREPORTER_MISSING.value:
            return False  # it has no evidence channel: it can never be in a record
        if enum_value in _SESSION_ONLY and prefix != "session":
            return False
        if enum_value in _CASE_LEVEL and prefix == "session":
            return False
        if enum_value == Outcome.L2_L3_NOT_PAIRED.value and prefix not in ("L3", "L2"):
            return False
        if prefix == "session" and enum_value not in _SESSION_ONLY | {Outcome.CASE_FAILED.value}:
            return False
    return True


def _check_structure(forms: list[str | None], trio_start: int | None) -> str | None:
    """Region order of the closed grammar; ``None`` when fine, else the reason code."""
    heading = forms.index("G3")
    count = len(forms)
    for form in forms[:heading]:
        if form in ("G7a", "G7b", "G7c"):
            return "interrupt_grammar_violation"
        if form not in ("G2", *_FORMS_PRE_TAIL):
            return "section_order_violation"
    i = heading + 1
    for wanted in ("G4a", "G4b", "G4c"):
        if i >= count or forms[i] != wanted:
            return "section_order_violation"
        i += 1
    while i < count and forms[i] in ("G1", "G5", "G6"):
        i += 1
    interrupted = False
    if trio_start is not None:
        if trio_start != i:
            return "interrupt_grammar_violation"
        i += 3
        interrupted = True
    while i < count and forms[i] in (*_FORMS_PRE_TAIL, "G8c"):
        i += 1
    counted = i < count and forms[i] in ("G8a", "G8b")
    if counted:
        i += 1
        while i < count and forms[i] == "G1":
            i += 1
    if counted and i == count:
        return None
    if interrupted and i < count and forms[i] in ("G5", "G6"):
        return "interrupt_grammar_violation"
    if not any(form in ("G8a", "G8b") for form in forms[heading:]):
        return "count_line_missing"
    return "section_order_violation"


def classify_capture(text: str, pipeline_status: int) -> tuple[str, str]:
    """``(verdict, "ok")`` or ``("discard", <reason code>)``; never raises, never echoes ``text``.

    ``pipeline_status`` is the overall pipeline status under ``pipefail`` (not necessarily
    pytest's own).  Verdicts: ``official`` and ``readiness_only`` (candidates, eligible for
    review and never an approval), ``failure_record`` (structurally safe, never evidence) and
    ``discard`` (delete the capture).
    """
    try:
        return _classify(text, pipeline_status)
    except Exception:
        return _discard("internal_error")


def _classify(text: str, status: int) -> tuple[str, str]:
    if type(status) is not int or not 0 <= status <= 255:
        return _discard("pipeline_status_invalid")
    if not isinstance(text, str):
        return _discard("internal_error")
    if text == "":
        return _discard("capture_empty")
    if _NON_PRINTABLE_RE.search(text) is not None:
        return _discard("non_ascii_or_control")
    lines = text.split("\n")
    forms = [_form_of(line) for line in lines]
    headings = forms.count("G3")
    if headings == 0:
        return _discard("no_evidence_section")
    if headings > 1:
        return _discard("multiple_evidence_sections")
    interrupt_at = [
        index
        for index, (form, line) in enumerate(zip(forms, lines, strict=True))
        if form in ("G7a", "G7b", "G7c") or (form is None and _looks_like_interrupt(line))
    ]
    trio_start: int | None = None
    if interrupt_at:
        first = interrupt_at[0]
        if interrupt_at != [first, first + 1, first + 2] or [forms[i] for i in interrupt_at] != [
            "G7a",
            "G7b",
            "G7c",
        ]:
            return _discard("interrupt_grammar_violation")
        trio_start = first
    if any(form is None for form in forms):
        return _discard("line_outside_grammar")
    problem = _check_structure(forms, trio_start)
    if problem is not None:
        return _discard(problem)

    records: list[dict[str, object]] = []
    for form, line in zip(forms, lines, strict=True):
        if form != "G5":
            continue
        parsed = _parse_record_line(line)
        if parsed is None:
            return _discard("evidence_json_malformed")
        try:
            validate_record(parsed)
        except EvidenceError:
            return _discard("evidence_record_invalid")
        kind = parsed.get("case")
        keys = set(parsed)
        if kind == "session":
            valid = keys == SESSION_KEYS
        elif kind in _REAL_CASES:
            valid = keys <= CASE_KEYS and "outcome" in keys and "canary_scan" in keys
        else:
            valid = "case" not in keys and keys <= RUN_KEYS
        if not valid:
            return _discard("evidence_record_invalid")
        records.append(parsed)
    session, cases, run, problem = _check_record_kinds(records)
    if problem is not None or run is None:
        return _discard(problem or "internal_error")

    g4 = {
        "skipped": int(lines[forms.index("G4a")].rsplit(" ", 1)[1]),
        "verdict": lines[forms.index("G4b")].rsplit(" ", 1)[1],
        "official": lines[forms.index("G4c")].rsplit(" ", 1)[1] == "true",
    }
    interrupted = trio_start is not None
    fallback = "G6" in forms
    collection = "G8c" in forms
    count_form = next(form for form in ("G8a", "G8b") if form in forms)
    counts = _count_entries(lines[forms.index(count_form)]) if count_form == "G8b" else None

    if (g4["verdict"] == "pass") != (g4["skipped"] == 0):
        return _discard("evidence_inconsistent")
    if "primary_failure" in run and (g4["official"] or status == 0):
        return _discard("evidence_inconsistent")
    if interrupted and status == 0:
        return _discard("evidence_inconsistent")  # an interrupted run cannot have succeeded
    if not _check_shape(session, cases, run):
        return _discard("evidence_inconsistent")

    clean_extras = not (fallback or interrupted or collection)
    quota = run.get("quota_attempts_total")
    official_records = (
        session is not None
        and session.get("git_dirty") is False
        and session.get("source_tree_verdict") == "verified"
        and session.get("isolation_verdict") == "isolated"
        and [r.get("outcome") for r in cases] == list(_OFFICIAL_OUTCOMES)
        and [r["case"] for r in cases] == list(CASE_NAMES)
        and "primary_failure" not in run
        and "not_executed" not in run
        and _is_int(quota)
        and 0 <= cast("int", quota) <= _QUOTA_ATTEMPT_LIMIT
        and all(_safe_case_record(r) for r in cases)
    )
    readiness_records = (
        session is None
        and len(cases) == 1
        and cases[0].get("case") == "L0"
        and cases[0].get("outcome") == Outcome.OK.value
        and "primary_failure" not in run
        and "not_executed" not in run
        and _safe_case_record(cases[0])
    )
    if g4["official"]:
        if status != 0:
            return _discard("pipeline_status_nonzero")
        if official_records and g4["skipped"] == 0 and clean_extras and _success_count(counts):
            return VERDICT_OFFICIAL, "ok"
        return _discard("evidence_inconsistent")
    if official_records and g4["skipped"] == 0:
        return _discard("evidence_inconsistent")  # the records say official: the G4 line disagrees
    if readiness_records and g4["skipped"] == 0 and clean_extras:
        if status != 0:
            return _discard("pipeline_status_nonzero")
        if _success_count(counts):
            return VERDICT_READINESS_ONLY, "ok"
        return _discard("evidence_inconsistent")
    return VERDICT_FAILURE_RECORD, "ok"


def _read_capture(path: str) -> tuple[str | None, str]:
    """``(text, "ok")`` or ``(None, <reason code>)``: read-only, at most 1 MiB, strict ASCII."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_CAPTURE_BYTES + 1)
    except FileNotFoundError:
        return None, "capture_missing"
    except (OSError, ValueError):
        return None, "capture_unreadable"
    if len(data) > MAX_CAPTURE_BYTES:
        return None, "capture_too_large"
    if not data:
        return None, "capture_empty"
    try:
        return data.decode("ascii"), "ok"
    except UnicodeDecodeError:
        return None, "non_ascii_or_control"


def _classify_arguments(argv: Sequence[str]) -> tuple[str, str]:
    """The exact argument grammar, then the capture (arguments are validated first)."""
    args = list(argv[1:])
    if not args or args[0] != CHECK_CAPTURE_OPTION or len(args) < 2:
        return _discard("usage_error")
    rest = args[2:]
    if not rest:
        return _discard("pipeline_status_invalid")  # the three-element form: no status
    if rest[0] != PIPELINE_STATUS_OPTION:
        return _discard("usage_error")
    if len(rest) == 1:
        return _discard("pipeline_status_invalid")  # an option without a value
    if len(rest) > 2:
        return _discard(
            "pipeline_status_invalid" if rest[2] == PIPELINE_STATUS_OPTION else "usage_error"
        )
    value = rest[1]
    if _STATUS_RE.fullmatch(value) is None or int(value) > 255:
        return _discard("pipeline_status_invalid")
    text, code = _read_capture(args[1])
    if text is None:
        return _discard(code)
    return classify_capture(text, int(value))


def classifier_main(argv: Sequence[str]) -> int:
    """Print exactly one verdict line and return the paired exit status (never raises)."""
    try:
        verdict, code = _classify_arguments(argv)
    except Exception:
        verdict, code = _discard("internal_error")
    if verdict not in VERDICT_EXIT_STATUS or (verdict == VERDICT_DISCARD) != (code != "ok"):
        verdict, code = _discard("internal_error")
    line = f"{verdict} {code}" if verdict == VERDICT_DISCARD else verdict
    sys.stdout.write(line + "\n")
    return VERDICT_EXIT_STATUS[verdict]


if __name__ == "__main__":
    sys.exit(classifier_main(sys.argv))


# ============================================================================
# Ordinary imports (never reached in classifier mode)
# ============================================================================

import asyncio
import collections
import contextlib
import dataclasses
import importlib
import importlib.util
import logging
import math
import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Awaitable, Iterator
from pathlib import Path
from typing import NoReturn, Protocol

import pytest

from conductor.exceptions import ProviderError

pytestmark = [
    pytest.mark.real_api,
    pytest.mark.skipif(
        os.environ.get("CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION") != "1",
        reason="requires CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION=1 (and -m real_api)",
    ),
]

GATE_ENV: Final = "CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION"
MODEL_ENV: Final = "CONDUCTOR_REAL_CLAUDE_MODEL"
REPO_ROOT: Final = Path(__file__).resolve().parents[2]
EXAMPLE_PATH: Final = REPO_ROOT / "examples" / "claude-agent-sdk-subscription.yaml"
DEFAULT_MODEL: Final = "claude-haiku-4-5"
DEFAULT_QUOTA_CEILING: Final = 3

# Names a sandbox needs to re-export so the *real* live tests run under pytester.
SANDBOX_EXPORTS: Final = (
    "pytestmark",
    "test_official_live_evidence",
    "test_readiness_probe_only",
    "_stub_claude_auth_readiness",
    "_register_zero_skip_reporter",
)

# A safety failure aborts every remaining case.
SAFETY_OUTCOMES: Final = frozenset(
    {
        Outcome.LIVE_OPT_IN_ERROR,
        Outcome.ISOLATION_FIXTURES_MISSING,
        Outcome.PREREQ_SDK_MISSING,
        Outcome.PREREQ_CLI_MISSING,
        Outcome.PREREQ_CLI_NOT_BUNDLED,
        Outcome.SOURCE_TREE_MISMATCH,
        Outcome.READINESS_STUB_ACTIVE,
        Outcome.PREREQ_PS_MISSING,
        Outcome.PREREQ_TERMINALREPORTER_MISSING,
        Outcome.PREREQ_REPORT_SANITIZER_UNAVAILABLE,
        Outcome.PREREQ_FILE_CONSOLE_ACTIVE,
        Outcome.INVALID_MODEL_OVERRIDE,
        Outcome.DESCENDANT_LEAK,
        Outcome.CANARY_LEAK,
        Outcome.CANARY_SCAN_INCOMPLETE,
        Outcome.L2_L3_NOT_PAIRED,
        Outcome.QUOTA_CEILING_EXCEEDED,
        Outcome.ADAPTERS_NOT_WIRED,
        Outcome.CANARY_USED_IN_L2,
    }
)


class HarnessFailure(Exception):
    """A fail-closed harness failure carrying one fixed :class:`Outcome`.

    ``detail`` must be a fixed string: never an environment value, credential, raw
    output or exception argument.
    """

    def __init__(
        self,
        outcome: Outcome,
        detail: str = "",
        *,
        extra: Mapping[str, object] | None = None,
    ) -> None:
        self.outcome = Outcome(outcome)
        self.detail = detail
        self.extra: dict[str, object] = dict(extra or {})
        super().__init__(f"{self.outcome.value}: {detail}" if detail else self.outcome.value)


class LiveOptInError(HarnessFailure):
    """One or both live gates are not active (a failure, never a skip)."""

    def __init__(self) -> None:
        super().__init__(Outcome.LIVE_OPT_IN_ERROR, "live opt-in gates are not both active")


def fail_fixed(message: str) -> NoReturn:
    """Fail the test with ``message`` only: no traceback and no chained exception text.

    pytest prints ``str()`` of every chained exception even with ``pytrace=False``, so a fixed
    failure raised while another exception is being handled (or with a ``__cause__``) would
    print that exception's message.  The context is suppressed.
    """
    try:
        pytest.fail(message, pytrace=False)
    except pytest.fail.Exception as failed:
        raise failed from None


def hand_over_failure(exc: HarnessFailure, config: Any) -> bool:
    """Path B: give the evidence plugin the one run-level record of a pre-``run_session`` failure.

    ``primary_failure`` is ``session:<enum>:<Class>`` -- no case wrapper can be active before
    ``run_session`` returns -- built only from the failure's fixed outcome and its own class name
    (never a message, ``detail``, ``extra``, path or foreign class).  Every selected case is
    ``not_executed_after_safety_failure``.  Returns ``False`` (and emits nothing) when there is no
    evidence plugin (a gate inactive), when the run-level record was already handed over (Path A
    got there first: a duplicate is never written), and for ``prereq_terminalreporter_missing``,
    which has no evidence channel.
    """
    if exc.outcome is Outcome.PREREQ_TERMINALREPORTER_MISSING:
        return False
    plugin = config.pluginmanager.get_plugin(ZERO_SKIP_PLUGIN_NAME)
    if plugin is None or plugin.run_record_emitted:
        return False
    not_executed = Outcome.NOT_EXECUTED_AFTER_SAFETY_FAILURE.value
    record = evidence(
        quota_attempts_total=0,
        quota_ceiling=DEFAULT_QUOTA_CEILING,
        primary_failure=f"session:{exc.outcome.value}:{exception_class_of(exc)}",
        not_executed=",".join(f"{case}:{not_executed}" for case in plugin.selected_cases),
    )
    return bool(plugin.hand_over(record))


def fail_closed(exc: HarnessFailure, config: Any) -> NoReturn:
    """Turn a harness failure into a test failure carrying only fixed text.

    Before failing, the run-level evidence record is handed to the evidence plugin that ``config``
    holds (Path B, :func:`hand_over_failure`).  A failure to build or emit it never replaces the
    fixed failure and is never printed, chained or retained.  Without an evidence plugin (a gate
    inactive) the fixed text is all there is.
    """
    with contextlib.suppress(Exception):
        hand_over_failure(exc, config)
    fail_fixed(f"{exc.outcome.value}:{exception_class_of(exc)}")


# ============================================================================
# Pure layer: gates
# ============================================================================


def markexpr_selects_real_api(expr: object) -> bool:
    """True iff ``expr`` is non-empty and evaluates true for the marker set ``{real_api}``.

    Uses pytest's private ``Expression`` (pinned by H12); any error fails closed.
    """
    if not isinstance(expr, str) or not expr.strip():
        return False
    try:
        from _pytest.mark.expression import Expression

        def matches(name: str, /, **_kwargs: object) -> bool:
            return name == "real_api"

        return bool(Expression.compile(expr).evaluate(matches))
    except Exception:
        return False


def _markexpr_of(config: Any) -> object:
    try:
        return config.getoption("markexpr")
    except Exception:
        return None


def require_live_optin(config: Any) -> None:
    """Raise :class:`LiveOptInError` unless both gates are active and this is no xdist worker."""
    if os.environ.get(GATE_ENV) != "1":
        raise LiveOptInError
    if not markexpr_selects_real_api(_markexpr_of(config)):
        raise LiveOptInError
    if os.environ.get("PYTEST_XDIST_WORKER") is not None:
        raise LiveOptInError
    if getattr(getattr(config, "option", None), "numprocesses", None) not in (None, 0):
        raise LiveOptInError


def gates_active(config: Any) -> bool:
    """Non-raising form of :func:`require_live_optin`."""
    try:
        require_live_optin(config)
    except LiveOptInError:
        return False
    return True


# ============================================================================
# Pure layer: isolation, source tree, git
# ============================================================================


def _co_file(fn: object) -> Path | None:
    code = getattr(fn, "__code__", None)
    filename = getattr(code, "co_filename", None)
    if not isinstance(filename, str):
        return None
    return Path(filename).resolve()


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def assert_live_isolation(
    tmp_path: Path,
    *,
    repo_root: Path = REPO_ROOT,
    runs_dir_fn: Callable[[], Path] | None = None,
    pid_dir_fn: Callable[[], Path] | None = None,
    gettempdir_fn: Callable[[], str] | None = None,
    environ: Mapping[str, str] | None = None,
    records_dir_fn: Callable[[], Path] | None = None,
    event_root_fn: Callable[[], Path] | None = None,
) -> None:
    """Prove the repository's isolation fixtures are active for *this* invocation.

    Static checks (1-3) never call a production function: a missing fixture would make such a
    call touch the real home or real temp directory.  Behavioural checks (4-7) run only after
    the static checks pass, so every call is confined to ``tmp_path``.  Any failure raises
    ``isolation_fixtures_missing``.  The keyword arguments exist so tests can pass fabricated
    objects; production use passes none.
    """
    fail = HarnessFailure(Outcome.ISOLATION_FIXTURES_MISSING)
    conftest = (repo_root / "tests" / "conftest.py").resolve()
    env = os.environ if environ is None else environ
    tmp_root = tmp_path.resolve()

    try:
        if runs_dir_fn is None:
            runs_dir_fn = importlib.import_module("conductor.rundir").runs_dir
        if pid_dir_fn is None:
            pid_dir_fn = importlib.import_module("conductor.cli.pid").pid_dir
        if gettempdir_fn is None:
            gettempdir_fn = tempfile.gettempdir

        # 1. Provenance: the current functions must come from this repo's tests/conftest.py.
        if _co_file(runs_dir_fn) != conftest or _co_file(pid_dir_fn) != conftest:
            raise fail
        # 2. Temp redirection.
        if _co_file(gettempdir_fn) != conftest:
            raise fail
        if Path(gettempdir_fn()).resolve() != tmp_root:
            raise fail
        for name in ("TMPDIR", "TEMP", "TMP"):
            value = env.get(name, "")
            if not value or Path(value).resolve() != tmp_root:
                raise fail
        # 3. CONDUCTOR_HOME containment (existence is not required).
        home = env.get("CONDUCTOR_HOME", "")
        if not home or not _is_inside(Path(home), tmp_root):
            raise fail

        # Behavioural checks.
        if records_dir_fn is None:
            records_dir_fn = importlib.import_module("conductor.fleet.records").run_records_dir
        if event_root_fn is None:
            event_root_fn = importlib.import_module("conductor.fleet.retention").event_log_root
        if not _is_inside(runs_dir_fn(), tmp_root):
            raise fail
        if not _is_inside(pid_dir_fn(), tmp_root):
            raise fail
        if not _is_inside(records_dir_fn(), tmp_root / "conductor-home"):
            raise fail
        if Path(event_root_fn()).resolve() != (tmp_root / "conductor").resolve():
            raise fail
    except HarnessFailure:
        raise
    except Exception as exc:
        raise fail from exc


def verify_source_tree(conductor_file: str | Path, test_file: str | Path) -> None:
    """``conductor`` must be imported from this test module's own repository."""
    expected = Path(test_file).resolve().parents[2] / "src" / "conductor"
    if not _is_inside(Path(conductor_file), expected):
        raise HarnessFailure(Outcome.SOURCE_TREE_MISMATCH)


def parse_git_state(rev_parse_output: str, porcelain_output: str) -> tuple[str, bool]:
    """Return ``(git_sha, dirty)``; a malformed SHA is a failure, never guessed."""
    sha = rev_parse_output.strip()
    if not _GIT_SHA_RE.fullmatch(sha):
        raise HarnessFailure(Outcome.CASE_FAILED, "git sha malformed")
    return sha, bool(porcelain_output.strip())


def _run_owned_subprocess(
    argv: Sequence[str],
    *,
    timeout: float = 5.0,
    cwd: Path | None = None,
    popen: Callable[..., Any] = subprocess.Popen,
) -> tuple[int, str, int]:
    """Run a subprocess this module owns: new session, bounded, killpg of its *own* group.

    Returns ``(returncode, stdout, pid)``.  ``os.killpg`` is only ever sent to the group of
    the process created here, never to a discovered PID.
    """
    proc = popen(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        cwd=cwd,
        text=True,
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    return proc.returncode, out or "", proc.pid


def read_git_state(
    config: Any,
    tmp_path: Path,
    *,
    run: Callable[[Sequence[str]], str] | None = None,
) -> tuple[str, bool]:
    require_live_optin(config)
    assert_live_isolation(tmp_path)

    def _default(argv: Sequence[str]) -> str:
        return _run_owned_subprocess(argv, cwd=REPO_ROOT)[1]

    runner = run or _default
    try:
        sha_out = runner(["git", "rev-parse", "HEAD"])
        status_out = runner(["git", "status", "--porcelain"])
    except (OSError, subprocess.SubprocessError) as exc:
        raise HarnessFailure(Outcome.CASE_FAILED, "git unavailable") from exc
    return parse_git_state(sha_out, status_out)


# ============================================================================
# Pure layer: canary
# ============================================================================

_CANARY_RE: Final = re.compile(r"sk-ant-api03-CANARY-([0-9a-f]{32})-DO-NOT-USE")
_MIN_FRAGMENT: Final = 12


class _NotAvailable:
    """Marks a stream that cannot exist for a case (no engine result, no console in L0)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "NOT_AVAILABLE"


NOT_AVAILABLE: Final = _NotAvailable()


def make_canary(uuid_hex: str | None = None) -> str:
    """A per-session invalid key; never sourced from the environment."""
    if uuid_hex is None:
        import uuid

        uuid_hex = uuid.uuid4().hex
    canary = f"sk-ant-api03-CANARY-{uuid_hex}-DO-NOT-USE"
    validate_canary(canary)
    return canary


def validate_canary(canary: str) -> None:
    if not isinstance(canary, str) or _CANARY_RE.fullmatch(canary) is None:
        raise HarnessFailure(Outcome.CANARY_SCAN_INCOMPLETE, "canary malformed")


def canary_fragments(canary: str) -> tuple[str, ...]:
    """The canary plus every 12-character window that overlaps its random part."""
    validate_canary(canary)
    match = _CANARY_RE.fullmatch(canary)
    assert match is not None
    start, end = match.span(1)
    fragments = {canary}
    for i in range(len(canary) - _MIN_FRAGMENT + 1):
        if i < end and i + _MIN_FRAGMENT > start:
            fragments.add(canary[i : i + _MIN_FRAGMENT])
    return tuple(sorted(fragments))


def exception_chain(exc: BaseException | None) -> list[BaseException]:
    """``exc`` plus everything reachable through ``__cause__``, ``__context__`` and groups."""
    seen: set[int] = set()
    out: list[BaseException] = []
    stack: list[BaseException] = [exc] if exc is not None else []
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        out.append(current)
        for nxt in (current.__cause__, current.__context__):
            if nxt is not None:
                stack.append(nxt)
        stack.extend(getattr(current, "exceptions", ()) or ())
    return out


def render_exception_chain(exc: BaseException | None) -> str:
    """``str`` and ``repr`` of every exception in the chain, for scanning only.

    An exception that can be rendered neither way cannot be scanned: that raises, so the caller
    reports an incomplete scan instead of a clean one.
    """
    parts: list[str] = []
    for item in exception_chain(exc):
        rendered = False
        for fn in (str, repr):
            try:
                parts.append(fn(item))
                rendered = True
            except Exception:
                parts.append("")
        if not rendered:
            raise ValueError("exception cannot be rendered")
    return "\n".join(parts)


def _stream_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, BaseException):
        return render_exception_chain(value)
    try:
        return json.dumps(value, default=repr, sort_keys=True)
    except Exception:
        return repr(value)  # raises when the value cannot be rendered: the scan is then incomplete


def read_tmp_files(tmp_path: Path, *, max_bytes: int = 2_000_000) -> str:
    """All readable file contents under ``tmp_path`` (bounded), for the canary scan."""
    chunks: list[str] = []
    budget = max_bytes
    for path in sorted(tmp_path.rglob("*")):
        if budget <= 0:
            break
        try:
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()[:budget]
                budget -= len(data)
                chunks.append(data.decode("utf-8", "replace"))
        except OSError:
            continue
    return "\n".join(chunks)


def scan_streams(canary: str, streams: Mapping[str, object]) -> list[str]:
    """Names of the streams that contain the canary or any fragment (>= 12 chars) of it."""
    fragments = canary_fragments(canary)
    hits: list[str] = []
    for name, value in streams.items():
        text = _stream_text(value)
        if any(fragment in text for fragment in fragments):
            hits.append(name)
    return hits


@dataclasses.dataclass(frozen=True)
class ScanReport:
    """The result of scanning the eight required streams: fixed strings and names only."""

    entries: tuple[str, ...]  # eight ``<stream>:<clean|leak|not_available>`` strings
    leaks: tuple[str, ...]  # names of the streams holding the canary
    incomplete: bool  # a stream was missing, unscannable or unavailable where not allowed


# A case that never reached its adapter produced no stream content, so nothing can have leaked.
EMPTY_SCAN: Final = tuple(
    f"{name}:{'not_available' if name == 'workflow_result' else 'clean'}"
    for name in REQUIRED_STREAMS
)


def scan_report(
    canary: str,
    streams: Mapping[str, object],
    *,
    case: object = None,
    forced_leaks: Iterable[str] = (),
) -> ScanReport:
    """Scan every required stream.  Never raises for a leak and never echoes matched text.

    A stream that is absent from ``streams`` is incomplete (the caller omitted it); one marked
    :data:`NOT_AVAILABLE` is incomplete unless :func:`unavailable_allowed`.  ``forced_leaks``
    names streams where a leak was already seen at emit time (a bounded buffer may have evicted
    the record).
    """
    fragments = canary_fragments(canary)
    forced = set(forced_leaks)
    entries: list[str] = []
    leaks: list[str] = []
    incomplete = False
    for name in REQUIRED_STREAMS:
        state = "clean"
        if name not in streams or streams[name] is NOT_AVAILABLE:
            state = "not_available"
            incomplete = incomplete or name not in streams or not unavailable_allowed(case, name)
        else:
            try:
                text = _stream_text(streams[name])
            except Exception:
                state = "not_available"
                incomplete = True
            else:
                if any(fragment in text for fragment in fragments):
                    state = "leak"
        if name in forced:
            state = "leak"
        if state == "leak":
            leaks.append(name)
        entries.append(f"{name}:{state}")
    return ScanReport(tuple(entries), tuple(leaks), incomplete)


def assert_no_canary(canary: str, streams: Mapping[str, object], *, case: object = None) -> None:
    """Fail closed if any retained stream holds the canary, or a category is missing.

    Every category in :data:`REQUIRED_STREAMS` must be supplied (a scan over fewer streams
    always "passes" and proves nothing).  Only fixed stream names are ever reported.
    """
    report = scan_report(canary, streams, case=case)
    if report.leaks:
        raise HarnessFailure(Outcome.CANARY_LEAK, "canary present in " + ",".join(report.leaks))
    if report.incomplete:
        raise HarnessFailure(Outcome.CANARY_SCAN_INCOMPLETE, "canary scan streams missing")


# ============================================================================
# Private log capture
# ============================================================================

# The only loggers the harness touches.  ``claude_agent_sdk`` covers every child logger through
# inheritance; the SDK logs raw CLI stdout at DEBUG, which must never reach a retained report.
PRIVATE_LOGGERS: Final = ("claude_agent_sdk", "conductor.providers.claude_agent_sdk")


class _BufferHandler(logging.Handler):
    """Bounded in-memory buffer; checks every record for the canary at emit time."""

    def __init__(self, canary: str, *, max_records: int = 2000, max_chars: int = 2000) -> None:
        super().__init__(level=logging.DEBUG)
        self._fragments = canary_fragments(canary)
        self._max_chars = max_chars
        self.records: collections.deque[str] = collections.deque(maxlen=max_records)
        self.leaked = False

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = self.format(record)
        except Exception:
            text = ""
        if any(fragment in text for fragment in self._fragments):
            self.leaked = True  # recorded now: the bounded buffer may evict the record later
        self.records.append(text[: self._max_chars])


class PrivateLogCapture:
    """Capture SDK and provider log records privately, for one case.

    While active, each logger of :data:`PRIVATE_LOGGERS` is set to ``DEBUG``, stops propagating
    and writes to a private buffer, so nothing reaches the root logger or pytest's report
    handlers.  Level, handlers, ``propagate`` and ``disabled`` are restored exactly on exit
    (success, failure, timeout and cancellation).  The root logger is never touched.
    """

    def __init__(self, canary: str, *, loggers: Sequence[str] = PRIVATE_LOGGERS) -> None:
        self._names = tuple(loggers)
        self._handler = _BufferHandler(canary)
        self._saved: list[tuple[logging.Logger, int, list[logging.Handler], bool, bool]] = []

    @property
    def leaked(self) -> bool:
        return self._handler.leaked

    @property
    def text(self) -> str:
        return "\n".join(self._handler.records)

    def __enter__(self) -> PrivateLogCapture:
        try:
            for name in self._names:
                logger = logging.getLogger(name)
                self._saved.append(
                    (logger, logger.level, list(logger.handlers), logger.propagate, logger.disabled)
                )
                logger.setLevel(logging.DEBUG)
                logger.propagate = False
                logger.disabled = False
                logger.addHandler(self._handler)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        while self._saved:
            logger, level, handlers, propagate, disabled = self._saved.pop()
            logger.removeHandler(self._handler)
            logger.setLevel(level)
            logger.propagate = propagate
            logger.disabled = disabled
            if logger.handlers != handlers:  # a handler added meanwhile is not ours to keep
                logger.handlers[:] = handlers


# ============================================================================
# Pure layer: model, CLI class, prerequisites
# ============================================================================


def validate_model(override: str | None) -> str:
    """The model to request: the default, or a strictly validated override."""
    if override is None:
        return DEFAULT_MODEL
    if _MODEL_RE.fullmatch(override) is None:
        raise HarnessFailure(Outcome.INVALID_MODEL_OVERRIDE)
    return override


def check_effective_model(effective: object) -> str:
    """The model the real ``agent_completed`` event reported; empty fails."""
    if not isinstance(effective, str) or not effective.strip():
        raise HarnessFailure(Outcome.EFFECTIVE_MODEL_MISSING)
    return effective


def check_priced(total_cost_usd: object) -> float:
    """An unpriced run never prints the label, so it cannot pass."""
    if (
        isinstance(total_cost_usd, bool)
        or not isinstance(total_cost_usd, int | float)
        or not math.isfinite(total_cost_usd)
        or total_cost_usd <= 0
    ):
        raise HarnessFailure(Outcome.UNPRICED_MODEL_LABEL_UNEXERCISED)
    return float(total_cost_usd)


def classify_cli(
    found: Path | None,
    *,
    bundled: Path,
    bundled_exists: bool,
    on_path: Path | None,
) -> str:
    """``bundled`` / ``path`` / ``fallback``; a non-bundled CLI when a bundled one exists fails."""
    if found is None:
        raise HarnessFailure(Outcome.PREREQ_CLI_MISSING)
    if found == bundled:
        return "bundled"
    if bundled_exists:
        raise HarnessFailure(Outcome.PREREQ_CLI_NOT_BUNDLED)
    return "path" if on_path is not None and found == on_path else "fallback"


def parse_cli_version(output: str) -> str:
    """First whitespace token of ``<cli> --version``, pattern-validated."""
    tokens = output.split()
    if not tokens or _CLI_VERSION_RE.fullmatch(tokens[0]) is None:
        raise HarnessFailure(Outcome.CASE_FAILED, "cli version malformed")
    return tokens[0]


def assert_real_readiness() -> None:
    """The repository's readiness stub must not be installed (``readiness_stub_active``)."""
    from conductor.providers.claude_agent_sdk import ClaudeAgentSdkProvider

    qualname = getattr(ClaudeAgentSdkProvider._check_auth_readiness, "__qualname__", "")
    if qualname != "ClaudeAgentSdkProvider._check_auth_readiness":
        raise HarnessFailure(Outcome.READINESS_STUB_ACTIVE)


def check_prerequisites(
    *,
    find_spec: Callable[[str], Any] | None = None,
    find_cli: Callable[[], Path | None] | None = None,
    which: Callable[[str], str | None] | None = None,
) -> str:
    """SDK importable, CLI found and bundled, ``ps`` available.  Returns the CLI class.

    Nothing is spawned: the SDK is located (not imported), the CLI path is only resolved.
    """
    find_spec = find_spec or importlib.util.find_spec
    which = which or shutil.which
    spec = find_spec("claude_agent_sdk")
    if spec is None:
        raise HarnessFailure(Outcome.PREREQ_SDK_MISSING)
    if find_cli is None:
        from conductor.providers.claude_agent_sdk import _find_claude_cli

        find_cli = _find_claude_cli
    locations = list(getattr(spec, "submodule_search_locations", None) or [])
    sdk_dir = Path(locations[0]) if locations else Path(spec.origin or "").parent
    bundled = sdk_dir / "_bundled" / ("claude.exe" if sys.platform == "win32" else "claude")
    path_hit = which("claude")
    cli_class = classify_cli(
        find_cli(),
        bundled=bundled,
        bundled_exists=bundled.is_file(),
        on_path=Path(path_hit) if path_hit else None,
    )
    if which("ps") is None:
        raise HarnessFailure(Outcome.PREREQ_PS_MISSING)
    return cli_class


def assert_session_console_ready() -> None:
    """At session start: verbose output active and no live ``_file_console`` (a second target)."""
    try:
        run_module = importlib.import_module("conductor.cli.run")
        app_module = importlib.import_module("conductor.cli.app")
        active = getattr(run_module, "_file_console", None) is not None
        verbose = bool(app_module.is_verbose())
    except Exception as exc:
        raise HarnessFailure(Outcome.PREREQ_FILE_CONSOLE_ACTIVE) from exc
    if active or not verbose:
        raise HarnessFailure(Outcome.PREREQ_FILE_CONSOLE_ACTIVE)


@dataclasses.dataclass(frozen=True)
class PreflightResult:
    model: str
    cli_class: str


def common_preflight(
    config: Any,
    tmp_path: Path,
    *,
    readiness_check: Callable[[], None] = assert_real_readiness,
    prereq_check: Callable[[], str] = check_prerequisites,
) -> PreflightResult:
    """Every check that must pass before *any* case, in the design's order."""
    require_live_optin(config)
    assert_live_isolation(tmp_path)
    assert_session_console_ready()
    plugin_manager = getattr(config, "pluginmanager", None)
    if plugin_manager is None or plugin_manager.get_plugin("terminalreporter") is None:
        raise HarnessFailure(Outcome.PREREQ_TERMINALREPORTER_MISSING)
    conductor = importlib.import_module("conductor")
    verify_source_tree(conductor.__file__ or "", __file__)
    readiness_check()
    cli_class = prereq_check()
    model = validate_model(os.environ.get(MODEL_ENV))
    return PreflightResult(model=model, cli_class=cli_class)


# ============================================================================
# Pure layer: quota
# ============================================================================


class QuotaCounter:
    """Counts *attempts* (not consumption) of inference-capable cases; refuses past the ceiling."""

    def __init__(self, ceiling: int = DEFAULT_QUOTA_CEILING) -> None:
        self.ceiling = ceiling
        self.attempts = 0

    def begin_attempt(self) -> None:
        if self.attempts >= self.ceiling:
            raise HarnessFailure(Outcome.QUOTA_CEILING_EXCEEDED, "attempt refused")
        self.attempts += 1


# ============================================================================
# Pure layer: descendants (report only)
# ============================================================================

DESCENDANT_DISCLAIMER: Final = (
    "no_descendants_remaining is not proof that nothing leaked: an orphan reparented to PID 1 "
    "or a subreaper is invisible to a descendant walk, and PID reuse can hide a leaked PID "
    "equal to a 'before' PID."
)

PsTable = dict[int, tuple[int, str]]


def short_name(command: str) -> str:
    """Basename of ``command``, at most 32 characters, unsafe characters replaced by ``?``."""
    base = command.strip().rsplit("/", 1)[-1]
    cleaned = re.sub(r"[^A-Za-z0-9._+-]", "?", base)[:32]
    return cleaned or "?"


def parse_ps(output: str, *, ps_pid: int | None = None) -> PsTable:
    """Parse ``ps -A -o pid=,ppid=,comm=`` rows (macOS and Linux); drop the ``ps`` child."""
    table: PsTable = {}
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\d+)\s+(\S.*?)\s*$", line)
        if match is None:
            continue
        pid, ppid = int(match.group(1)), int(match.group(2))
        if ps_pid is not None and pid == ps_pid:
            continue
        table[pid] = (ppid, short_name(match.group(3)))
    return table


def descendants(table: Mapping[int, tuple[int, str]], root: int) -> set[int]:
    """Transitive descendants of ``root`` (excluding ``root`` itself)."""
    children: dict[int, list[int]] = {}
    for pid, (ppid, _name) in table.items():
        children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    stack = list(children.get(root, ()))
    while stack:
        pid = stack.pop()
        if pid in found or pid == root:
            continue
        found.add(pid)
        stack.extend(children.get(pid, ()))
    return found


def read_ps_table(*, popen: Callable[..., Any] = subprocess.Popen) -> PsTable:
    """Read the real process table.  Unguarded: use :func:`descendant_snapshot` in live paths."""
    try:
        _rc, out, ps_pid = _run_owned_subprocess(
            ["ps", "-A", "-o", "pid=,ppid=,comm="], popen=popen
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HarnessFailure(Outcome.PREREQ_PS_MISSING) from exc
    return parse_ps(out, ps_pid=ps_pid)


def descendant_snapshot(
    config: Any, tmp_path: Path, *, popen: Callable[..., Any] = subprocess.Popen
) -> PsTable:
    require_live_optin(config)
    assert_live_isolation(tmp_path)
    return read_ps_table(popen=popen)


@dataclasses.dataclass(frozen=True)
class DescendantReport:
    verdict: Outcome
    remaining: list[dict[str, object]]
    disclaimer: str = DESCENDANT_DISCLAIMER


async def observe_descendants(
    read_table: Callable[[], Mapping[int, tuple[int, str]]],
    root_pid: int,
    before: frozenset[int],
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    grace_s: float = 10.0,
    interval_s: float = 0.25,
) -> DescendantReport:
    """Grace period, then one final observation.  Reports; never signals anything."""
    deadline = clock() + grace_s
    while True:
        if not descendants(read_table(), root_pid) - before or clock() >= deadline:
            break
        await sleep(interval_s)
    final = read_table()
    remaining = descendants(final, root_pid) - before
    if not remaining:
        return DescendantReport(Outcome.NO_DESCENDANTS_REMAINING, [])
    rows: list[dict[str, object]] = [
        {"pid": pid, "name": final[pid][1]} for pid in sorted(remaining)
    ]
    return DescendantReport(Outcome.DESCENDANT_LEAK, rows)


# ============================================================================
# Pure layer: typed observations and the L3 classifier
# ============================================================================

# ``claude_agent_sdk.types.AssistantMessageError`` (pinned against the SDK by H12).
ASSISTANT_ERRORS: Final = frozenset(
    {
        "authentication_failed",
        "billing_error",
        "rate_limit",
        "invalid_request",
        "server_error",
        "unknown",
    }
)


@dataclasses.dataclass(frozen=True)
class Observation:
    """Typed fields only: never text, content or usage."""

    type_name: str
    assistant_error: str | None
    api_error_status: int | None
    is_error: bool | None


def record_observation(message: object) -> Observation:
    """Total: reduces any message to its typed signals (never raises, never stores content)."""
    raw_error = getattr(message, "error", None)
    assistant_error: str | None
    if raw_error is None:
        assistant_error = None
    elif isinstance(raw_error, str) and raw_error in ASSISTANT_ERRORS:
        assistant_error = raw_error
    else:
        assistant_error = "other"
    status = getattr(message, "api_error_status", None)
    api_status = (
        status
        if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599
        else None
    )
    raw_is_error = getattr(message, "is_error", None)
    is_error = raw_is_error if isinstance(raw_is_error, bool) else None
    return Observation(type(message).__name__[:64], assistant_error, api_status, is_error)


def _event_type(event: Any) -> object:
    if isinstance(event, Mapping):
        return event.get("type")
    return getattr(event, "type", None)


def _has_completed(events: Sequence[object]) -> bool:
    return any(_event_type(e) == "agent_completed" for e in events)


def classify_l3(
    observations: Sequence[Observation],
    exc_chain: Sequence[BaseException],
    events: Sequence[object],
) -> Outcome:
    """Exactly one fixed enum from typed signals; never from message text."""
    if _has_completed(events):
        return Outcome.FELL_BACK_TO_LOGIN
    non_retryable = any(
        isinstance(exc, ProviderError) and exc.is_retryable is False for exc in exc_chain
    )
    if non_retryable:
        if any(
            o.assistant_error == "authentication_failed" or o.api_error_status == 401
            for o in observations
        ):
            return Outcome.INVALID_KEY
        if any(o.api_error_status == 404 for o in observations):
            return Outcome.MODEL_UNAVAILABLE
    return Outcome.INCONCLUSIVE


# ============================================================================
# Pure layer: passive observer
# ============================================================================


async def _observe(inner: Any, sink: list[Observation]) -> Any:
    """Re-yield ``inner`` unchanged, recording typed signals; always close ``inner`` explicitly."""
    try:
        async for message in inner:
            sink.append(record_observation(message))
            yield message
    finally:
        aclose = getattr(inner, "aclose", None)
        if aclose is not None:
            await aclose()


def make_spy(original: Callable[..., Any], sink: list[Observation]) -> Callable[..., Any]:
    """A plain function that calls ``original`` exactly once and wraps its iterator."""

    def spy(self: Any, *args: Any, **kwargs: Any) -> Any:
        inner = original(self, *args, **kwargs)
        return _observe(inner, sink)

    return spy


def install_spy(monkeypatch: pytest.MonkeyPatch, cls: Any, sink: list[Observation]) -> None:
    """Install the spy on ``cls.receive_response`` (call inside ``monkeypatch.context()``)."""
    monkeypatch.setattr(cls, "receive_response", make_spy(cls.receive_response, sink))


# ============================================================================
# Pure layer: variants and pairing
# ============================================================================

_AUTH_MODE_PATH: Final = "workflow.runtime.provider.auth_mode"
_SELECTOR_NAMES: Final = ("CLAUDE_CODE_OAUTH_TOKEN",) + tuple(
    f"CLAUDE_CODE_USE_{name}" for name in ("BEDROCK", "VERTEX", "FOUNDRY")
)


class Case(enum.StrEnum):
    L0 = "L0"
    L1 = "L1"
    L3 = "L3"
    L2 = "L2"


ORDER: Final = (Case.L0, Case.L1, Case.L3, Case.L2)
INFERENCE_CASES: Final = frozenset({Case.L1, Case.L3, Case.L2})
EXPECTED_OUTCOME: Final = {
    Case.L0: Outcome.OK,
    Case.L1: Outcome.OK,
    Case.L3: Outcome.INVALID_KEY,
    Case.L2: Outcome.OK,
}


@dataclasses.dataclass(frozen=True)
class EnvPlan:
    """Environment names (and hidden values) for one case; values never appear in ``repr``."""

    set_names: tuple[str, ...]
    removed_names: tuple[str, ...]
    values: Mapping[str, str] = dataclasses.field(default_factory=dict, repr=False, compare=False)


@dataclasses.dataclass(frozen=True)
class CaseVariant:
    case: Case
    auth_mode: str
    config: Mapping[str, Any]
    env: EnvPlan


def scrub_route_names(environ: Mapping[str, str]) -> tuple[str, ...]:
    """Route variables present in ``environ``: every ``ANTHROPIC_*`` plus the fixed selectors."""
    names = {n for n in environ if n.startswith("ANTHROPIC_")}
    names |= {n for n in _SELECTOR_NAMES if n in environ}
    return tuple(sorted(names))


def build_env_plan(environ: Mapping[str, str], canary: str) -> EnvPlan:
    return EnvPlan(
        set_names=("ANTHROPIC_API_KEY",),
        removed_names=scrub_route_names(environ),
        values={"ANTHROPIC_API_KEY": canary},
    )


def _with_auth_mode(
    base: Mapping[str, Any], auth_mode: str, model: str | None = None
) -> dict[str, Any]:
    import copy

    doc = copy.deepcopy(dict(base))
    doc["workflow"]["runtime"]["provider"]["auth_mode"] = auth_mode
    if model is not None:
        doc["workflow"]["runtime"]["default_model"] = model
    return doc


def build_variants(
    yaml_text: str, canary: str, environ: Mapping[str, str], model: str | None = None
) -> dict[Case, CaseVariant]:
    """L1 (clean baseline), L3 (``auto``) and L2 (``subscription``) from one document.

    L3 and L2 share the canary environment and differ only in ``auth_mode``; L1 runs the
    shipped ``subscription`` document with the route variables scrubbed and no canary.
    ``model`` (the validated override, if any) is applied identically to all three.
    """
    import yaml

    base = yaml.safe_load(yaml_text)
    canary_env = build_env_plan(environ, canary)
    clean_env = EnvPlan((), scrub_route_names(environ), {})
    return {
        Case.L1: CaseVariant(
            Case.L1, "subscription", _with_auth_mode(base, "subscription", model), clean_env
        ),
        Case.L3: CaseVariant(Case.L3, "auto", _with_auth_mode(base, "auto", model), canary_env),
        Case.L2: CaseVariant(
            Case.L2, "subscription", _with_auth_mode(base, "subscription", model), canary_env
        ),
    }


def config_diff_paths(a: Any, b: Any, prefix: str = "") -> list[str]:
    """Dotted paths at which two nested structures differ."""
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        paths: list[str] = []
        for key in sorted(set(a) | set(b), key=str):
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in a or key not in b:
                paths.append(child)
            else:
                paths.extend(config_diff_paths(a[key], b[key], child))
        return paths
    if isinstance(a, list | tuple) and isinstance(b, list | tuple):
        if len(a) != len(b):
            return [prefix]
        paths = []
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            paths.extend(config_diff_paths(x, y, f"{prefix}[{i}]"))
        return paths
    return [] if a == b else [prefix]


def assert_config_paired(l3: CaseVariant, l2: CaseVariant) -> None:
    """L3 and L2 configurations may differ only in ``auth_mode`` (``auto`` vs ``subscription``)."""
    if config_diff_paths(l3.config, l2.config) != [_AUTH_MODE_PATH]:
        raise HarnessFailure(Outcome.L2_L3_NOT_PAIRED, "configuration differs beyond auth_mode")
    if (l3.auth_mode, l2.auth_mode) != ("auto", "subscription"):
        raise HarnessFailure(Outcome.L2_L3_NOT_PAIRED, "auth modes are not auto/subscription")


def assert_env_paired(l3: CaseVariant, l2: CaseVariant) -> None:
    """Environment names (set and removed) must be identical sets; values must match."""
    if set(l3.env.set_names) != set(l2.env.set_names):
        raise HarnessFailure(Outcome.L2_L3_NOT_PAIRED, "environment names set differ")
    if set(l3.env.removed_names) != set(l2.env.removed_names):
        raise HarnessFailure(Outcome.L2_L3_NOT_PAIRED, "environment names removed differ")
    if dict(l3.env.values) != dict(l2.env.values):
        raise HarnessFailure(Outcome.L2_L3_NOT_PAIRED, "environment values differ")


# ============================================================================
# Pure layer: per-case findings and outcome precedence
# ============================================================================


def interrupt_kind(exc: BaseException) -> str:
    """The fixed ``interrupted`` value for a non-``Exception`` ``BaseException``."""
    if isinstance(exc, KeyboardInterrupt):
        return "keyboard_interrupt"
    if isinstance(exc, asyncio.CancelledError):
        return "cancelled"
    return "other_base_exception"


_SCAN_RANK: Final = {"not_available": 0, "clean": 1, "leak": 2}


@dataclasses.dataclass
class CaseFindings:
    """What one case's scan, descendant observation and cleanup found (fixed values only).

    The adapter, the descendant check and the case wrapper all write here, so a finding survives
    whichever of them is unwound by a cancellation.
    """

    case: Case
    scan: dict[str, str] = dataclasses.field(default_factory=dict)  # stream -> state
    incomplete: bool = False
    descendants: Outcome | None = None
    descendant_report: list[dict[str, object]] = dataclasses.field(default_factory=list)
    cleanup_failed: list[str] = dataclasses.field(default_factory=list)

    def _merge(self, name: str, state: str) -> None:
        if _SCAN_RANK[state] >= _SCAN_RANK[self.scan.get(name, "not_available")]:
            self.scan[name] = state

    def record_streams(
        self, canary: str, streams: Mapping[str, object], *, forced_leaks: Iterable[str] = ()
    ) -> None:
        """Scan ``streams``; a leak, once seen, is never overwritten by a later clean scan."""
        report = scan_report(canary, streams, case=self.case, forced_leaks=forced_leaks)
        for entry in report.entries:
            name, state = entry.split(":")
            self._merge(name, state)
        self.incomplete = self.incomplete or report.incomplete

    def record_evidence(self, canary: str, record: Mapping[str, object]) -> None:
        """Scan the evidence about to be retained (the ``evidence`` stream)."""
        try:
            text = _stream_text(dict(record))
        except Exception:
            self.incomplete = True
            return
        state = "leak" if any(f in text for f in canary_fragments(canary)) else "clean"
        self._merge("evidence", state)

    @property
    def entries(self) -> tuple[str, ...]:
        """The eight ``canary_scan`` strings; a case that never ran has produced nothing."""
        base = dict(entry.split(":") for entry in EMPTY_SCAN)
        base.update(self.scan)
        return tuple(f"{name}:{base[name]}" for name in REQUIRED_STREAMS)

    @property
    def canary_leak(self) -> bool:
        return "leak" in self.scan.values()

    @property
    def descendant_leak(self) -> bool:
        return self.descendants is Outcome.DESCENDANT_LEAK


class FindingsBoard:
    """One :class:`CaseFindings` per case; ``canary`` lets the case wrapper scan the evidence."""

    def __init__(self, canary: str | None = None) -> None:
        self.canary = canary
        self._cases: dict[Case, CaseFindings] = {}

    def begin(self, case: Case) -> CaseFindings:
        self._cases[case] = CaseFindings(case)
        return self._cases[case]

    def for_case(self, case: Case) -> CaseFindings:
        return self._cases.setdefault(case, CaseFindings(case))


@dataclasses.dataclass(frozen=True)
class Resolution:
    primary: Outcome
    secondary: tuple[Outcome, ...]
    adapter_outcome: Outcome


def resolve_outcome(
    adapter_outcome: Outcome,
    *,
    canary_leak: bool,
    descendant_leak: bool,
    scan_incomplete: bool,
) -> Resolution:
    """Ordinary outcomes, highest first: canary leak, descendant leak, incomplete scan, adapter.

    Neither leak is ever lost: the primary is one fixed enum, the other leak is secondary, and
    the adapter outcome is always retained.  Cancellation never comes here: it is always
    primary and is re-raised unchanged.
    """
    canary = canary_leak or adapter_outcome is Outcome.CANARY_LEAK
    descendant = descendant_leak or adapter_outcome is Outcome.DESCENDANT_LEAK
    if canary:
        secondary = (Outcome.DESCENDANT_LEAK,) if descendant else ()
        return Resolution(Outcome.CANARY_LEAK, secondary, adapter_outcome)
    if descendant:
        return Resolution(Outcome.DESCENDANT_LEAK, (), adapter_outcome)
    if scan_incomplete or adapter_outcome is Outcome.CANARY_SCAN_INCOMPLETE:
        return Resolution(Outcome.CANARY_SCAN_INCOMPLETE, (), adapter_outcome)
    return Resolution(adapter_outcome, (), adapter_outcome)


# ============================================================================
# Pure layer: the ordered state machine
# ============================================================================


@dataclasses.dataclass(frozen=True)
class CaseOutcome:
    outcome: Outcome
    fields: Mapping[str, object] = dataclasses.field(default_factory=dict)


CaseRunner = Callable[[Case], Awaitable["CaseOutcome | Outcome"]]


@dataclasses.dataclass
class CaseResult:
    case: Case
    status: str  # ok | failed | not_executed | interrupted
    outcome: Outcome
    exc_class: str | None = None
    secondary: tuple[Outcome, ...] = ()
    adapter_outcome: Outcome | None = None


@dataclasses.dataclass
class SessionResult:
    expected_cases: tuple[Case, ...]
    results: list[CaseResult]
    quota_attempts: int
    quota_ceiling: int
    evidence: list[dict[str, object]]
    session_failure: tuple[Outcome, str] | None = None

    @property
    def succeeded(self) -> bool:
        """Every intended case ran, in order, with exactly its intended outcome."""
        if self.session_failure is not None:
            return False
        if tuple(r.case for r in self.results) != self.expected_cases:
            return False
        return all(r.status == "ok" and r.outcome == EXPECTED_OUTCOME[r.case] for r in self.results)

    @property
    def primary_failure(self) -> str:
        if self.session_failure is not None:
            outcome, cls = self.session_failure
            return f"session:{outcome.value}:{cls}"
        for r in self.results:
            if r.status in ("failed", "interrupted"):
                return f"{r.case.value}:{r.outcome.value}:{r.exc_class or 'none'}"
        return "none:incomplete:none"

    @property
    def not_executed(self) -> str:
        return ",".join(
            f"{r.case.value}:{r.outcome.value}" for r in self.results if r.status == "not_executed"
        )


def not_executed_value(case: Case, outcome: Outcome) -> Outcome | None:
    """The transition function: ``None`` proceeds, otherwise the value recorded for later cases."""
    if outcome in SAFETY_OUTCOMES:
        return Outcome.NOT_EXECUTED_AFTER_SAFETY_FAILURE
    if case is Case.L0:
        return None if outcome is Outcome.OK else Outcome.NOT_EXECUTED_AFTER_L0_FAILURE
    if case is Case.L1:
        return None if outcome is Outcome.OK else Outcome.NOT_EXECUTED_AFTER_L1_FAILURE
    if case is Case.L3:
        return {
            Outcome.INVALID_KEY: None,
            Outcome.FELL_BACK_TO_LOGIN: Outcome.NOT_EXECUTED_L3_FELL_BACK_TO_LOGIN,
            Outcome.MODEL_UNAVAILABLE: Outcome.NOT_EXECUTED_L3_MODEL_UNAVAILABLE,
        }.get(outcome, Outcome.NOT_EXECUTED_L3_INCONCLUSIVE)
    return None


def secondary_findings_of(findings: CaseFindings) -> tuple[Outcome, ...]:
    """The safety findings a cancelled case reports as secondary evidence (fixed values only)."""
    return tuple(
        finding
        for finding, present in (
            (Outcome.CANARY_LEAK, findings.canary_leak),
            (Outcome.DESCENDANT_LEAK, findings.descendant_leak),
        )
        if present
    )


def fallback_failure_marker(case: Case) -> str:
    """The only text reported when even the fallback record cannot be emitted."""
    return f"evidence_fallback_failed: {Case(case).value}"


def _fallback_record(
    findings: CaseFindings, canary: str | None, *, case: Case, interrupt: BaseException
) -> dict[str, object]:
    """The record for a cancelled case whose normal record could not be assembled.

    Built only from the findings already collected (never from the failed normal record), so a
    canary or descendant finding is never lost; the cancellation stays primary.  May raise
    :class:`EvidenceError`: the caller then reports the fixed marker only.
    """
    record: dict[str, object] = {
        "case": case.value,
        "outcome": Outcome.INTERRUPTED,
        "adapter_outcome": Outcome.INTERRUPTED,
        "interrupted": interrupt_kind(interrupt),
        "exception_class": exception_class_of(interrupt),
        "cleanup_failed": ordered_cleanup(findings.cleanup_failed),
    }
    if findings.descendants is not None:
        record["descendants"] = findings.descendants
        if findings.descendant_leak:
            record["descendant_report"] = list(findings.descendant_report)
    if canary is not None:
        findings.record_evidence(canary, record)
    record["secondary_findings"] = [o.value for o in secondary_findings_of(findings)]
    record["canary_scan"] = list(findings.entries)
    return evidence(**record)


def _case_record(
    findings: CaseFindings,
    canary: str | None,
    *,
    case: Case,
    started: float,
    clock: Callable[[], float],
    attempted: bool,
    exc_class: str | None,
    fields: Mapping[str, object],
    adapter_outcome: Outcome,
    interrupt: BaseException | None,
) -> tuple[dict[str, object], Resolution, str | None]:
    """Assemble one sanitized case record and its resolution (may raise :class:`EvidenceError`)."""
    record: dict[str, object] = {
        "case": case.value,
        "attempted_quota_execution": attempted,
        "elapsed_s": round(clock() - started, 3),
    }
    if exc_class is not None:
        record["exception_class"] = exc_class
    record.update(fields)
    if exc_class is None and isinstance(record.get("exception_class"), str):
        exc_class = str(record["exception_class"])  # the case's own exception, from its fields
    if findings.descendants is not None:
        record["descendants"] = findings.descendants
        if findings.descendant_leak:
            record["descendant_report"] = list(findings.descendant_report)
    if findings.cleanup_failed:
        record["cleanup_failed"] = ordered_cleanup(findings.cleanup_failed)
    if canary is not None:
        findings.record_evidence(canary, record)
    if interrupt is not None:
        resolution = Resolution(
            Outcome.INTERRUPTED, secondary_findings_of(findings), Outcome.INTERRUPTED
        )
        kind = interrupt_kind(interrupt)
    else:
        resolution = resolve_outcome(
            adapter_outcome,
            canary_leak=findings.canary_leak,
            descendant_leak=findings.descendant_leak,
            scan_incomplete=findings.incomplete,
        )
        kind = "none"
        if exc_class is None and resolution.primary is not adapter_outcome:
            exc_class = "HarnessFailure"  # the harness would have raised the safety outcome
            record["exception_class"] = exc_class
    record.update(
        outcome=resolution.primary,
        adapter_outcome=resolution.adapter_outcome,
        secondary_findings=[o.value for o in resolution.secondary],
        interrupted=kind,
        canary_scan=list(findings.entries),
    )
    return record, resolution, exc_class


async def run_ordered_cases(
    runners: Mapping[Case, CaseRunner],
    *,
    quota: QuotaCounter,
    emit: Callable[[dict[str, object]], None],
    cases: Sequence[Case] = ORDER,
    pre_hooks: Mapping[Case, Callable[[], None]] | None = None,
    clock: Callable[[], float] = time.monotonic,
    board: FindingsBoard | None = None,
    mark: Callable[[str], None] | None = None,
) -> SessionResult:
    """Run ``cases`` in order with injected runners; nothing is ever skipped.

    This is the case wrapper: after every case, whatever happened, the findings on ``board`` are
    resolved by :func:`resolve_outcome` and one sanitized record (with its ``canary_scan``) is
    emitted.  ``KeyboardInterrupt``, ``CancelledError`` and any other non-``Exception``
    ``BaseException`` are recorded (findings are secondary), every later case is marked
    ``not_executed_after_interrupt``, and the *original exception object* is re-raised.
    """
    findings_board = board if board is not None else FindingsBoard()
    result = SessionResult(tuple(cases), [], 0, quota.ceiling, [])

    def _emit(record: dict[str, object]) -> None:
        result.evidence.append(record)
        emit(record)

    pending: Outcome | None = None
    for case in cases:
        if pending is not None:
            result.results.append(CaseResult(case, "not_executed", pending))
            continue
        findings = findings_board.begin(case)
        started = clock()
        adapter_outcome, exc_class = Outcome.CASE_FAILED, None
        fields: dict[str, object] = {}
        attempted = False
        interrupt: BaseException | None = None
        try:
            if pre_hooks and case in pre_hooks:
                pre_hooks[case]()
            if case in INFERENCE_CASES:
                quota.begin_attempt()
                attempted = True
            raw = await runners[case](case)
            case_outcome = raw if isinstance(raw, CaseOutcome) else CaseOutcome(Outcome(raw))
            adapter_outcome = Outcome(case_outcome.outcome)
            fields = dict(case_outcome.fields)
        except HarnessFailure as exc:
            adapter_outcome, exc_class = exc.outcome, exception_class_of(exc)
            fields = dict(exc.extra)
        except Exception as exc:
            adapter_outcome = Outcome.INCONCLUSIVE if case is Case.L3 else Outcome.CASE_FAILED
            exc_class = exception_class_of(exc)
        except BaseException as exc:  # cancellation / interrupt: recorded, never converted
            interrupt, adapter_outcome = exc, Outcome.INTERRUPTED
            exc_class = exception_class_of(exc)

        canary = findings_board.canary
        try:
            record, resolution, exc_class = _case_record(
                findings,
                canary,
                case=case,
                started=started,
                clock=clock,
                attempted=attempted,
                exc_class=exc_class,
                fields=fields,
                adapter_outcome=adapter_outcome,
                interrupt=interrupt,
            )
            _emit(evidence(**record))
        except Exception:
            if interrupt is None:
                raise
            # The interrupt stays primary.  The normal record is discarded; the fallback is built
            # from the findings already collected, and its failure is reported by a fixed marker.
            findings.cleanup_failed.append("evidence")
            resolution = Resolution(
                Outcome.INTERRUPTED, secondary_findings_of(findings), Outcome.INTERRUPTED
            )
            try:
                _emit(_fallback_record(findings, canary, case=case, interrupt=interrupt))
            except Exception:
                with contextlib.suppress(Exception):
                    if mark is not None:
                        mark(fallback_failure_marker(case))
        status = (
            "interrupted"
            if interrupt is not None
            else ("ok" if resolution.primary == EXPECTED_OUTCOME[case] else "failed")
        )
        result.results.append(
            CaseResult(
                case, status, resolution.primary, exc_class, resolution.secondary, adapter_outcome
            )
        )
        if interrupt is not None:
            for later in cases[list(cases).index(case) + 1 :]:
                result.results.append(
                    CaseResult(later, "not_executed", Outcome.NOT_EXECUTED_AFTER_INTERRUPT)
                )
            result.quota_attempts = quota.attempts
            with contextlib.suppress(Exception):
                _emit(run_level_record(result))
            raise interrupt
        pending = not_executed_value(case, resolution.primary)
    result.quota_attempts = quota.attempts
    return result


async def run_session(
    *,
    preflight: Callable[[], object],
    runners: Mapping[Case, CaseRunner],
    quota: QuotaCounter,
    emit: Callable[[dict[str, object]], None],
    cases: Sequence[Case] = ORDER,
    pre_hooks: Mapping[Case, Callable[[], None]] | None = None,
    board: FindingsBoard | None = None,
    mark: Callable[[str], None] | None = None,
) -> SessionResult:
    """Preflight first; a failure runs no case (``not_executed_after_safety_failure``)."""
    try:
        preflight()
    except HarnessFailure as exc:
        return SessionResult(
            tuple(cases),
            [
                CaseResult(c, "not_executed", Outcome.NOT_EXECUTED_AFTER_SAFETY_FAILURE)
                for c in cases
            ],
            quota.attempts,
            quota.ceiling,
            [],
            session_failure=(exc.outcome, exception_class_of(exc)),
        )
    return await run_ordered_cases(
        runners, quota=quota, emit=emit, cases=cases, pre_hooks=pre_hooks, board=board, mark=mark
    )


def aggregate_text(result: SessionResult) -> str:
    """Fixed text: every ``case:enum`` in order, the primary failure and any secondary finding."""
    listing = ",".join(f"{r.case.value}:{r.outcome.value}" for r in result.results)
    text = f"cases: {listing}; first_failure: {result.primary_failure}"
    also = ",".join(f"{r.case.value}:{o.value}" for r in result.results for o in r.secondary)
    return f"{text}; also: {also}" if also else text


def finalize(result: SessionResult) -> None:
    """One aggregate failure unless every intended outcome was reached."""
    if not result.succeeded:
        fail_fixed(aggregate_text(result))


def run_level_record(result: SessionResult) -> dict[str, object]:
    record: dict[str, object] = {
        "quota_attempts_total": result.quota_attempts,
        "quota_ceiling": result.quota_ceiling,
    }
    if result.not_executed:
        record["not_executed"] = result.not_executed
    if not result.succeeded:
        record["primary_failure"] = result.primary_failure
    return evidence(**record)


async def _observe_into(
    findings: CaseFindings,
    read_table: Callable[[], Mapping[int, tuple[int, str]]],
    root_pid: int,
    before: frozenset[int],
    *,
    guard: bool,
    clock: Callable[[], float],
    sleep: Callable[[float], Awaitable[object]],
    grace_s: float,
    interval_s: float,
) -> None:
    """Observe descendants and record the verdict; ``guard`` swallows an observation failure."""
    try:
        report = await observe_descendants(
            read_table,
            root_pid,
            before,
            clock=clock,
            sleep=sleep,
            grace_s=grace_s,
            interval_s=interval_s,
        )
    except Exception:
        if not guard:
            raise
        findings.cleanup_failed.append("descendants")
        return
    findings.descendants = report.verdict
    findings.descendant_report = list(report.remaining)


def with_descendant_check(
    runner: CaseRunner,
    *,
    read_table: Callable[[], Mapping[int, tuple[int, str]]],
    root_pid: int,
    board: FindingsBoard | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    grace_s: float = 10.0,
    interval_s: float = 0.25,
) -> CaseRunner:
    """Wrap a runner with the report-only before / grace / final descendant observation.

    The verdict is recorded on the case's findings and the runner's result -- or its exception,
    the *same object*, including a cancellation -- passes through unchanged.  The case wrapper
    (:func:`run_ordered_cases`) applies the outcome precedence.
    """

    async def wrapped(case: Case) -> CaseOutcome | Outcome:
        findings = board.for_case(case) if board is not None else CaseFindings(case)
        before = frozenset(descendants(read_table(), root_pid))
        options: dict[str, Any] = {
            "clock": clock,
            "sleep": sleep,
            "grace_s": grace_s,
            "interval_s": interval_s,
        }
        try:
            outcome = await runner(case)
        except BaseException:
            await _observe_into(findings, read_table, root_pid, before, guard=True, **options)
            raise
        await _observe_into(findings, read_table, root_pid, before, guard=False, **options)
        return outcome

    return wrapped


# ============================================================================
# Report sanitizer
# ============================================================================

REPORT_SANITIZER_NAME: Final = "claude-subscription-report-sanitizer"
UNEXPECTED_EXCEPTION_TEXT: Final = "unexpected exception"
HARNESS_FAILURE_TEXT: Final = "harness failure"
INTERRUPT_BANNER: Final = "KeyboardInterrupt"
INTERRUPT_LINE: Final = "interrupted: details withheld"

_OUTCOME_ALT: Final = "|".join(sorted(o.value for o in Outcome))
_CASE_ALT: Final = "L0|L1|L3|L2"
_CLASS_PATTERN: Final = "[A-Za-z_][A-Za-z0-9_]{0,63}"
_CASE_OUTCOME: Final = f"(?:{_CASE_ALT}):(?:{_OUTCOME_ALT})"
# The fixed texts the harness itself fails with: a prerequisite (``<outcome>:<Class>``) and the
# aggregate of ``aggregate_text``.  Nothing else is ever rendered as an expected failure.
_FIXED_FAILURE_RES: Final = (
    re.compile(f"(?:{_OUTCOME_ALT}):{_CLASS_PATTERN}", re.ASCII),
    re.compile(
        f"cases: {_CASE_OUTCOME}(?:,{_CASE_OUTCOME})*; first_failure: "
        f"(?:(?:{_CASE_ALT}|session):(?:{_OUTCOME_ALT}):(?:{_CLASS_PATTERN}|none)"
        f"|none:incomplete:none)(?:; also: {_CASE_OUTCOME}(?:,{_CASE_OUTCOME})*)?",
        re.ASCII,
    ),
)


def is_fixed_failure_text(text: object) -> bool:
    """True iff ``text`` is exactly one of the harness's fixed failure forms."""
    return type(text) is str and any(rx.fullmatch(text) for rx in _FIXED_FAILURE_RES)


def unexpected_exception_text(exc: object) -> str:
    """``unexpected exception: <Class>`` for a safe ASCII class name, else the bare form."""
    name = exception_class_of(exc) if exc is not None else UNKNOWN_EXCEPTION
    if name == UNKNOWN_EXCEPTION:
        return UNEXPECTED_EXCEPTION_TEXT
    return f"{UNEXPECTED_EXCEPTION_TEXT}: {name}"


def render_failure(excinfo: object) -> str:
    """The only text a failed report may carry, derived from fixed forms only.

    An expected harness failure renders its fixed text if (and only if) it fits the fixed
    grammar; every other exception -- including ``CancelledError`` -- renders its ASCII class name.
    The message, context, cause, traceback, source, arguments and paths are never read.
    """
    try:
        exc = getattr(excinfo, "value", None)
        if isinstance(exc, pytest.fail.Exception):
            message = getattr(exc, "msg", None)
            if isinstance(message, str) and is_fixed_failure_text(message):
                return message
            return HARNESS_FAILURE_TEXT
        return unexpected_exception_text(exc)
    except Exception:
        return UNEXPECTED_EXCEPTION_TEXT


class _InterruptCrash:
    """Stands in for ``ExceptionRepr.reprcrash``: a fixed banner and no location."""

    message = INTERRUPT_BANNER

    def toterminal(self, tw: Any) -> None:
        tw.line(INTERRUPT_LINE)


class FixedInterruptRecord:
    """Stands in for the interrupt record pytest keeps: carries no message, path or frames."""

    reprcrash = _InterruptCrash()

    def toterminal(self, tw: Any) -> None:
        tw.line(INTERRUPT_LINE)


class ReportSanitizer:
    """Renders every failure and interrupt from fixed text; only the *rendering* changes.

    The original exception objects, the harness's re-raise, the exit status and all control flow
    are untouched.  Registered only under both gates (:func:`register_report_sanitizer`).
    """

    def __init__(self, reporter: Any | None = None) -> None:
        self._reporter = reporter

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_makereport(self, item: Any, call: Any) -> Any:
        report = yield
        if getattr(report, "failed", False):
            try:
                text = render_failure(getattr(call, "excinfo", None))
            except Exception:
                text = UNEXPECTED_EXCEPTION_TEXT
            with contextlib.suppress(Exception):
                report.sections = []
            with contextlib.suppress(Exception):
                report.longrepr = text
        return report

    @pytest.hookimpl(wrapper=True)
    def pytest_keyboard_interrupt(self, excinfo: Any) -> Any:
        try:
            return (yield)
        finally:
            reporter = self._reporter
            if reporter is not None:
                with contextlib.suppress(Exception):
                    reporter._keyboardinterrupt_memo = FixedInterruptRecord()


def register_report_sanitizer(config: Any) -> ReportSanitizer:
    """Register once per config, before anything else; fail closed if pytest cannot support it.

    Needs ``pytest_keyboard_interrupt`` and, when a terminal reporter exists, its interrupt record
    (``_keyboardinterrupt_memo``, pinned by H12).  A missing reporter is reported by the next
    prerequisite, not here.
    """
    manager = config.pluginmanager
    existing = manager.get_plugin(REPORT_SANITIZER_NAME)
    if existing is not None:
        return existing
    try:
        if not hasattr(config.hook, "pytest_keyboard_interrupt"):
            raise AttributeError("pytest_keyboard_interrupt")
        reporter = manager.get_plugin("terminalreporter")
        if reporter is not None and not hasattr(reporter, "_keyboardinterrupt_memo"):
            raise AttributeError("_keyboardinterrupt_memo")
        plugin = ReportSanitizer(reporter)
        manager.register(plugin, REPORT_SANITIZER_NAME)
    except Exception:
        raise HarnessFailure(Outcome.PREREQ_REPORT_SANITIZER_UNAVAILABLE) from None
    return plugin


# ============================================================================
# Zero-skip plugin
# ============================================================================

ZERO_SKIP_PLUGIN_NAME: Final = "claude-subscription-zero-skip"


def is_real_skip(report: object) -> bool:
    """A skipped report that is not an expected-xfail (``wasxfail`` unset in any phase)."""
    return getattr(report, "outcome", None) == "skipped" and not hasattr(report, "wasxfail")


OFFICIAL_TEST_NAME: Final = "test_official_live_evidence"
READINESS_TEST_NAME: Final = "test_readiness_probe_only"


def selected_cases_of(items: Iterable[object]) -> tuple[str, ...]:
    """The cases of the selected run, from the collected items (``request.session.items``).

    ``test_official_live_evidence`` selects L0, L1, L3, L2; ``test_readiness_probe_only`` alone
    selects L0; both, or neither (fail safe), give the superset L0, L1, L3, L2.
    """
    names = {getattr(item, "name", None) for item in items}
    if OFFICIAL_TEST_NAME not in names and READINESS_TEST_NAME in names:
        return ("L0",)
    return CASE_NAMES


def pytest_version_text() -> str:
    """``pytest.__version__`` if it fits the fixed grammar, else exactly ``unavailable``."""
    version = getattr(pytest, "__version__", None)
    if isinstance(version, str) and _PYTEST_VERSION_RE.fullmatch(version):
        return version
    return UNAVAILABLE


def plugin_names_of(config: Any) -> list[str]:
    """Sorted, de-duplicated ``<name>==<version>`` of the distribution plugins, or ``unavailable``.

    Public APIs only (``config.pluginmanager.list_plugin_distinfo()``, ``Distribution.metadata``
    and ``.version``); a plugin loaded by ``-p`` or a ``conftest`` is not a distribution plugin.
    Any problem, a malformed entry or more than 32 entries gives exactly ``["unavailable"]``.
    """
    try:
        entries = {
            f"{dist.metadata['Name']}=={dist.version}"
            for _plugin, dist in config.pluginmanager.list_plugin_distinfo()
        }
        names = sorted(entries)
        if len(names) <= MAX_PLUGINS and all(_PLUGIN_RE.fullmatch(name) for name in names):
            return names
    except Exception:
        pass
    return [UNAVAILABLE]


def run_diagnostics(config: Any = None) -> dict[str, object]:
    """The ``pytest_version`` and ``plugins`` fields of every run-level record (design 9.3)."""
    return {
        "pytest_version": pytest_version_text(),
        "plugins": plugin_names_of(config) if config is not None else [UNAVAILABLE],
    }


class ZeroSkipPlugin:
    """The evidence plugin: session-wide count of real skips and the retained evidence lines.

    Fails a passing session when a skip occurred, never a failing one.  Holds the selected case
    set, the single ``run_record_emitted`` flag (the two-path invariant: whichever of Path A and
    Path B hands over the run-level record first wins, a later hand-over is refused) and the
    diagnostics added to that record.  ``official``, ``skipped_reports`` and ``zero_skip_verdict``
    exist only as the three G4 section lines written by :meth:`pytest_terminal_summary`.
    """

    def __init__(
        self,
        seed: int = 0,
        *,
        selected_cases: Sequence[str] = CASE_NAMES,
        diagnostics: Mapping[str, object] | None = None,
    ) -> None:
        self.skipped_reports = seed
        self.evidence_lines: list[str] = []
        self.ordered_test_passed = False
        self.git_dirty = True
        self.canary_scans_complete = False
        self.selected_cases: tuple[str, ...] = tuple(selected_cases)
        self.run_record_emitted = False
        self.diagnostics: dict[str, object] = (
            dict(diagnostics) if diagnostics is not None else run_diagnostics()
        )

    @property
    def zero_skip_verdict(self) -> str:
        return "pass" if self.skipped_reports == 0 else "fail"

    @property
    def official(self) -> bool:
        return (
            self.ordered_test_passed
            and self.skipped_reports == 0
            and not self.git_dirty
            and self.canary_scans_complete
        )

    def hand_over(self, record: Mapping[str, object]) -> bool:
        """Append the run-level record (with the diagnostics); refused if one was already handed."""
        if self.run_record_emitted:
            return False
        line = emit_evidence({**record, **self.diagnostics})
        self.evidence_lines.append(line)
        self.run_record_emitted = True
        return True

    def pytest_runtest_logreport(self, report: object) -> None:
        if is_real_skip(report):
            self.skipped_reports += 1

    def pytest_sessionfinish(self, session: Any, exitstatus: object) -> None:
        if self.skipped_reports > 0 and int(exitstatus) == 0:  # ty: ignore[invalid-argument-type]
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(
        self, terminalreporter: Any, exitstatus: object, config: Any
    ) -> None:
        terminalreporter.section("claude subscription live evidence")
        terminalreporter.write_line(f"skipped_reports: {self.skipped_reports}")
        terminalreporter.write_line(f"zero_skip_verdict: {self.zero_skip_verdict}")
        terminalreporter.write_line(f"official: {'true' if self.official else 'false'}")
        for line in self.evidence_lines:
            terminalreporter.write_line(line)


def register_zero_skip_plugin(config: Any, items: Iterable[object] = ()) -> ZeroSkipPlugin:
    """Register the evidence plugin once per config, seeded from reports that preceded it.

    The terminal-reporter lookup is inert (it renders nothing and runs no prerequisite); with no
    reporter there is no evidence channel and the failure is ``prereq_terminalreporter_missing``.
    ``items`` (``request.session.items``) fixes the selected case set once, at registration.
    """
    manager = config.pluginmanager
    existing = manager.get_plugin(ZERO_SKIP_PLUGIN_NAME)
    if existing is not None:
        return existing
    reporter = manager.get_plugin("terminalreporter")
    if reporter is None:
        raise HarnessFailure(Outcome.PREREQ_TERMINALREPORTER_MISSING)
    seed = sum(1 for r in reporter.stats.get("skipped", []) if is_real_skip(r))
    plugin = ZeroSkipPlugin(
        seed, selected_cases=selected_cases_of(items), diagnostics=run_diagnostics(config)
    )
    manager.register(plugin, ZERO_SKIP_PLUGIN_NAME)
    return plugin


@pytest.fixture(scope="session", autouse=True)
def _register_zero_skip_reporter(request: pytest.FixtureRequest) -> ZeroSkipPlugin | None:
    """Acts only when both gates are active; never unregisters (sessionfinish comes later).

    The order is normative: (a) both gates; (b) the terminal-reporter lookup, which is inert;
    (c) the evidence plugin, so that every later failure can be recorded; (d) the report
    sanitizer, as the very next statement after (c); (e) every other prerequisite and live
    operation.  Two boundaries this order does not close are rejected by the capture classifier,
    not assumed away: a failure while registering the evidence plugin leaves no evidence section,
    and a failure or interrupt in the window between (c) and (d) leaves a section followed by
    pytest's default rendering.  Reaching this fixture therefore guarantees nothing about every
    line of a capture; only the classifier verdict does.
    """
    if not gates_active(request.config):
        return None
    try:
        plugin = register_zero_skip_plugin(request.config, request.session.items)
        register_report_sanitizer(request.config)
    except HarnessFailure as exc:
        fail_closed(exc, request.config)
    return plugin


@pytest.fixture(autouse=True)
def _stub_claude_auth_readiness() -> None:
    """Deliberately does nothing: overrides the conftest fixture of the same name.

    The readiness stub would otherwise hide the real check (``readiness_stub_active``).
    ``claude_auth_readiness_mocked`` is *not* used: it installs a spawn tripwire.
    """


# ============================================================================
# External adapter seams: what each real adapter provides, and what tests replace
# ============================================================================


@dataclasses.dataclass(frozen=True)
class ReadinessObservation:
    ready: bool
    fields: Mapping[str, object] = dataclasses.field(default_factory=dict)
    streams: Mapping[str, object] | None = None


@dataclasses.dataclass(frozen=True)
class RunObservation:
    """What one workflow-engine execution produced, reduced to safe, typed data."""

    events: Sequence[object]
    exception: BaseException | None
    streams: Mapping[str, object]
    total_cost_usd: float | None = None
    effective_model: str | None = None
    fields: Mapping[str, object] = dataclasses.field(default_factory=dict)
    output: Mapping[str, object] | None = None
    usage: Mapping[str, object] | None = None
    console_text: str = ""


@dataclasses.dataclass(frozen=True)
class CliEvidence:
    cli_class: str
    version: str


class ReadinessAdapter(Protocol):
    async def probe(self) -> ReadinessObservation: ...


class WorkflowExecutionAdapter(Protocol):
    async def execute(self, variant: CaseVariant) -> RunObservation: ...


class CliEvidenceAdapter(Protocol):
    def resolve(self) -> CliEvidence: ...


class DescendantSnapshotAdapter(Protocol):
    def snapshot(self) -> Mapping[int, tuple[int, str]]: ...


class ObserverInstaller(Protocol):
    def observing(self) -> contextlib.AbstractContextManager[list[Observation]]: ...


@dataclasses.dataclass(frozen=True)
class AdapterSet:
    readiness: ReadinessAdapter
    workflow: WorkflowExecutionAdapter
    cli: CliEvidenceAdapter
    descendants: DescendantSnapshotAdapter
    observer: ObserverInstaller
    board: FindingsBoard = dataclasses.field(default_factory=FindingsBoard)


# ============================================================================
# Real adapters: the production paths behind the seams
# ============================================================================
#
# Every adapter enforces the gate and the isolation prerequisite as its first two statements,
# creates its environment / patch scope with an *independent* ``monkeypatch.context()`` per
# case, and records its scan on the case's findings for success, failure *and* cancellation.
# Nothing here reads a credential, an auth payload value, ``~/.claude`` or a Keychain entry.

LIVE_QUESTION: Final = "In one short sentence, what is a workflow?"
CASE_TIMEOUTS_S: Final = {Case.L1: 120.0, Case.L3: 90.0, Case.L2: 120.0}


def reportable_names(names: Iterable[str]) -> list[str]:
    """Environment variable *names* that the evidence contract can carry (never values)."""
    return sorted({n for n in names if _ENV_NAME_RE.fullmatch(n)})


def apply_env_plan(mp: pytest.MonkeyPatch, plan: EnvPlan) -> None:
    """Remove the route variables, then set the plan's variables (canary only, L3 and L2)."""
    for name in plan.removed_names:
        mp.delenv(name, raising=False)
    for name in plan.set_names:
        mp.setenv(name, plan.values[name])


def first_party_constant(api_provider: object, constant: str) -> str:
    """``unexercised`` when the CLI reported none, else ``validated`` or ``mismatch``."""
    if api_provider is None:
        return "unexercised"
    return "validated" if api_provider == constant else "mismatch"


def readiness_fields(status: Any, billing: tuple[str, str], first_party: str) -> dict[str, object]:
    """L0 evidence: presence booleans and fixed enums only, never a raw auth value."""
    api_provider = getattr(status, "api_provider", None)
    return {
        "auth_method_present": getattr(status, "auth_method", None) is not None,
        "api_provider_present": api_provider is not None,
        "api_provider_is_first_party": api_provider == first_party,
        "subscription_type_present": bool((getattr(status, "subscription_type", "") or "").strip()),
        "api_key_source_present": getattr(status, "api_key_source", None) is not None,
        "billing_mode": billing[0],
        "billing_reason": billing[1],
        "first_party_constant": first_party_constant(api_provider, first_party),
    }


def build_streams(
    *,
    stdout_stderr: str,
    console: object,
    logs: str,
    exception: BaseException | None,
    events: object,
    workflow_result: object,
    tmp_path: Path,
    evidence_fields: Mapping[str, object],
) -> dict[str, object]:
    """One entry per :data:`REQUIRED_STREAMS` name (the canary scan needs every category)."""
    return {
        "stdout_stderr": stdout_stderr,
        "console": console,
        "logs": logs,
        "exceptions": exception,
        "events": events,
        "workflow_result": workflow_result,
        "evidence": dict(evidence_fields),
        "tmp_files": read_tmp_files(tmp_path),
    }


def _drain(capture: Any) -> str:
    """Everything ``capfd`` captured on file descriptors 1 and 2 since the last drain."""
    if capture is None:
        return ""
    out, err = capture.readouterr()
    return f"{out}\n{err}"


def record_case_scan(
    board: FindingsBoard,
    case: Case,
    canary: str,
    logs: PrivateLogCapture,
    streams: Mapping[str, object],
) -> None:
    """Scan ``streams`` onto the case's findings; a leak seen at log-emit time is kept."""
    board.for_case(case).record_streams(
        canary, streams, forced_leaks=("logs",) if logs.leaked else ()
    )


class RealReadinessAdapter:
    """L0: provider built as the factory builds it, real readiness, real billing derivation."""

    def __init__(
        self,
        config: Any,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        capfd: Any,
        canary: str,
        board: FindingsBoard,
        example_path: Path = EXAMPLE_PATH,
    ) -> None:
        self._config = config
        self._tmp_path = tmp_path
        self._monkeypatch = monkeypatch
        self._capfd = capfd
        self._canary = canary
        self._board = board
        self._example_path = example_path

    async def probe(self) -> ReadinessObservation:
        require_live_optin(self._config)
        assert_live_isolation(self._tmp_path)
        from conductor.config.loader import load_config
        from conductor.providers import claude_agent_sdk as sdk
        from conductor.providers.factory import create_provider

        runtime = load_config(self._example_path).workflow.runtime
        removed = scrub_route_names(os.environ)
        fields: dict[str, object] = {}
        status: Any = None
        failure: BaseException | None = None
        streams: dict[str, object] = {}
        with self._monkeypatch.context() as mp, PrivateLogCapture(self._canary) as logs:
            for name in removed:
                mp.delenv(name, raising=False)
            try:
                provider = cast(
                    Any,
                    await create_provider(
                        provider_type="claude-agent-sdk",
                        validate=False,
                        default_model=runtime.default_model,
                        max_session_seconds=runtime.max_session_seconds,
                        provider_settings=runtime.provider,
                    ),
                )
                try:
                    context = provider._capture_auth_context(str(self._tmp_path))
                    status = await provider._check_auth_readiness(context=context)
                    billing = sdk._derive_billing(context, status)
                finally:
                    await provider.close()
                fields = readiness_fields(status, billing, sdk._FIRST_PARTY_API_PROVIDER)
                fields["env_names_removed"] = reportable_names(removed)
            except BaseException as exc:  # scanned below, then propagates unchanged
                failure = exc
                raise
            finally:
                streams = build_streams(
                    stdout_stderr=_drain(self._capfd),
                    console=NOT_AVAILABLE,
                    logs=logs.text,
                    exception=failure,
                    events=NOT_AVAILABLE,
                    workflow_result=NOT_AVAILABLE,
                    tmp_path=self._tmp_path,
                    evidence_fields=fields,
                )
                record_case_scan(self._board, Case.L0, self._canary, logs, streams)
        return ReadinessObservation(bool(status.ready), fields, streams)


class RealWorkflowAdapter:
    """L1 / L3 / L2 through ``load_config``, ``ProviderRegistry`` and ``WorkflowEngine``."""

    def __init__(
        self,
        config: Any,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        capfd: Any,
        canary: str,
        board: FindingsBoard,
        timeouts: Mapping[Case, float] = CASE_TIMEOUTS_S,
        question: str = LIVE_QUESTION,
    ) -> None:
        self._config = config
        self._tmp_path = tmp_path
        self._monkeypatch = monkeypatch
        self._capfd = capfd
        self._canary = canary
        self._board = board
        self._timeouts = dict(timeouts)
        self._question = question

    def _fields(
        self, variant: CaseVariant, usage: Mapping[str, object] | None, started: float
    ) -> dict[str, object]:
        fields: dict[str, object] = {
            "env_names_set": reportable_names(variant.env.set_names),
            "env_names_removed": reportable_names(variant.env.removed_names),
            "elapsed_s": round(time.monotonic() - started, 3),
        }
        for key, source in (
            ("input_tokens", "total_input_tokens"),
            ("output_tokens", "total_output_tokens"),
        ):
            value = (usage or {}).get(source)
            if _is_int(value):
                fields[key] = value
        return fields

    async def execute(self, variant: CaseVariant) -> RunObservation:
        require_live_optin(self._config)
        assert_live_isolation(self._tmp_path)
        import io

        import yaml
        from rich.console import Console

        from conductor.cli.run import display_usage_summary
        from conductor.config.loader import load_config
        from conductor.engine.workflow import WorkflowEngine
        from conductor.events import WorkflowEventEmitter
        from conductor.providers.registry import ProviderRegistry

        path = self._tmp_path / f"workflow-{variant.case.value}.yaml"
        path.write_text(yaml.safe_dump(dict(variant.config)))
        events: list[dict[str, Any]] = []
        console_buffer = io.StringIO()
        result: Mapping[str, object] | None = None
        usage: Mapping[str, object] | None = None
        failure: BaseException | None = None
        fields: dict[str, object] = {}
        streams: dict[str, object] = {}
        started = time.monotonic()
        with self._monkeypatch.context() as mp, PrivateLogCapture(self._canary) as logs:
            apply_env_plan(mp, variant.env)
            try:
                cfg = load_config(path)
                async with ProviderRegistry(cfg) as registry:
                    emitter = WorkflowEventEmitter()
                    emitter.subscribe(lambda event: events.append(event.to_dict()))
                    engine = WorkflowEngine(
                        cfg, registry=registry, event_emitter=emitter, workflow_path=path
                    )
                    result = await asyncio.wait_for(
                        engine.run({"question": self._question}),
                        self._timeouts[variant.case],
                    )
                usage = engine.get_execution_summary()["usage"]
                display_usage_summary(
                    dict(usage),
                    console=Console(file=console_buffer, force_terminal=False, width=120),
                )
            except Exception as exc:  # returned as an observation; the state machine decides
                failure = exc
            except BaseException as exc:  # cancellation / interrupt: scanned below, then re-raised
                failure = exc
                raise
            finally:
                fields = self._fields(variant, usage, started)
                streams = build_streams(
                    stdout_stderr=_drain(self._capfd),
                    console=console_buffer.getvalue(),
                    logs=logs.text,
                    exception=failure,
                    events=events,
                    workflow_result=result if result is not None else NOT_AVAILABLE,
                    tmp_path=self._tmp_path,
                    evidence_fields=fields,
                )
                record_case_scan(self._board, variant.case, self._canary, logs, streams)
        completed = [e for e in events if e.get("type") == "agent_completed"]
        data = _event_data(completed[-1]) if completed else {}
        model = data.get("model")
        cost = (usage or {}).get("total_cost_usd")
        return RunObservation(
            events=events,
            exception=failure,
            streams=streams,
            total_cost_usd=float(cost)
            if isinstance(cost, int | float) and _is_float(cost)
            else None,
            effective_model=model if isinstance(model, str) else None,
            fields=fields,
            output=result,
            usage=usage,
            console_text=console_buffer.getvalue(),
        )


class RealObserverInstaller:
    """The passive spy on the real ``ClaudeSDKClient.receive_response``, one case at a time."""

    def __init__(self, config: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._config = config
        self._tmp_path = tmp_path
        self._monkeypatch = monkeypatch

    @contextlib.contextmanager
    def observing(self) -> Iterator[list[Observation]]:
        require_live_optin(self._config)
        assert_live_isolation(self._tmp_path)
        try:
            client_class = importlib.import_module("claude_agent_sdk").ClaudeSDKClient
        except Exception as exc:
            raise HarnessFailure(Outcome.PREREQ_SDK_MISSING) from exc
        original = client_class.receive_response
        sink: list[Observation] = []
        with self._monkeypatch.context() as mp:
            install_spy(mp, client_class, sink)
            yield sink
        if client_class.receive_response is not original:
            raise HarnessFailure(Outcome.CASE_FAILED, "observer patch not restored")


class RealDescendantAdapter:
    """Process-table snapshots only through the guarded :func:`descendant_snapshot`."""

    def __init__(self, config: Any, tmp_path: Path) -> None:
        self._config = config
        self._tmp_path = tmp_path

    def snapshot(self) -> Mapping[int, tuple[int, str]]:
        require_live_optin(self._config)
        assert_live_isolation(self._tmp_path)
        return descendant_snapshot(self._config, self._tmp_path)


class RealCliEvidenceAdapter:
    """CLI class and version through :func:`resolve_cli_evidence` (``<cli> --version`` only)."""

    def __init__(
        self,
        config: Any,
        tmp_path: Path,
        *,
        find_cli: Callable[[], Path | None] | None = None,
        run: Callable[[Sequence[str]], str] | None = None,
    ) -> None:
        self._config = config
        self._tmp_path = tmp_path
        self._find_cli = find_cli
        self._run = run

    def resolve(self) -> CliEvidence:
        require_live_optin(self._config)
        assert_live_isolation(self._tmp_path)
        return resolve_cli_evidence(
            self._config, self._tmp_path, find_cli=self._find_cli, run=self._run
        )


def configured_adapters(
    pytestconfig: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: Any,
    *,
    canary: str,
) -> AdapterSet:
    """The production adapter set; any construction failure is ``adapters_not_wired``.

    ``capfd`` supplies the ``stdout_stderr`` stream: pytest refuses ``capfd`` and ``capsys`` in
    one test, and ``capfd`` also captures everything written to ``sys.stdout`` / ``sys.stderr``.
    One :class:`FindingsBoard` is shared by every adapter and the case wrapper.
    """
    require_live_optin(pytestconfig)
    assert_live_isolation(tmp_path)
    try:
        validate_canary(canary)
        board = FindingsBoard(canary)
        return AdapterSet(
            readiness=RealReadinessAdapter(
                pytestconfig, tmp_path, monkeypatch, capfd=capfd, canary=canary, board=board
            ),
            workflow=RealWorkflowAdapter(
                pytestconfig, tmp_path, monkeypatch, capfd=capfd, canary=canary, board=board
            ),
            cli=RealCliEvidenceAdapter(pytestconfig, tmp_path),
            descendants=RealDescendantAdapter(pytestconfig, tmp_path),
            observer=RealObserverInstaller(pytestconfig, tmp_path, monkeypatch),
            board=board,
        )
    except HarnessFailure:
        raise
    except Exception as exc:
        raise HarnessFailure(Outcome.ADAPTERS_NOT_WIRED) from exc


async def run_case(config: Any, tmp_path: Path, case: Case, runner: CaseRunner) -> Any:
    require_live_optin(config)
    assert_live_isolation(tmp_path)
    return await runner(case)


SUBSCRIPTION_REASON: Final = "first_party_login"
_L0_BOOLEANS: Final = (
    "auth_method_present",
    "api_provider_present",
    "api_provider_is_first_party",
    "subscription_type_present",
    "api_key_source_present",
)


def _safe_fields(fields: Mapping[str, object]) -> dict[str, object]:
    """Only allowlisted evidence keys, for attaching to a record."""
    return {k: v for k, v in fields.items() if k in EVIDENCE_KEYS}


def assert_l0_success(ready: bool, fields: Mapping[str, object]) -> dict[str, object]:
    """L0 success is asserted, not merely recorded (R0a, R1a, R1b, R1c).

    Order: readiness, evidence completeness, first-party constant, billing derivation, then
    the subscription-type / API-key-source contradictions.  Returns the evidence fields.
    """
    safe = {**_safe_fields(fields), "ready": ready}

    def fail(outcome: Outcome) -> NoReturn:
        raise HarnessFailure(outcome, extra=safe)

    if ready is not True:
        fail(Outcome.NOT_LOGGED_IN)
    if any(not isinstance(fields.get(name), bool) for name in _L0_BOOLEANS):
        fail(Outcome.READINESS_EVIDENCE_MISSING)
    if fields.get("first_party_constant") not in _FIRST_PARTY:
        fail(Outcome.READINESS_EVIDENCE_MISSING)
    if not isinstance(fields.get("billing_mode"), str) or not isinstance(
        fields.get("billing_reason"), str
    ):
        fail(Outcome.READINESS_EVIDENCE_MISSING)
    if fields["first_party_constant"] == "mismatch":
        fail(Outcome.FIRST_PARTY_MISMATCH)
    if fields["billing_mode"] != "subscription" or fields["billing_reason"] != SUBSCRIPTION_REASON:
        fail(Outcome.BILLING_NOT_SUBSCRIPTION)
    if fields["subscription_type_present"] is not True or fields["api_key_source_present"] is True:
        fail(Outcome.READINESS_EVIDENCE_CONTRADICTION)
    return safe


def _l0_runner(adapters: AdapterSet, canary: str) -> CaseRunner:
    async def run(case: Case) -> CaseOutcome | Outcome:
        observation = await adapters.readiness.probe()
        if observation.streams is not None:
            adapters.board.for_case(case).record_streams(canary, observation.streams)
        return CaseOutcome(
            Outcome.OK, assert_l0_success(observation.ready, dict(observation.fields))
        )

    return run


def _event_data(event: object) -> Mapping[str, object]:
    data: object
    if isinstance(event, Mapping):
        data = cast("Mapping[str, object]", event).get("data")
    else:
        data = getattr(event, "data", None)
    return cast("Mapping[str, object]", data) if isinstance(data, Mapping) else {}


def assert_inference_success(observed: RunObservation, requested_model: str) -> dict[str, object]:
    """The L1 / L2 success predicate; every failure is one fixed outcome.

    Requires: structured output, ``agent_completed`` with ``billing_mode == "subscription"``,
    an aggregate billing state of ``subscription``, requested and effective models, a priced
    (non-zero) estimate, and the real billing label in the real ``display_usage_summary``
    output.  Returns the evidence fields.
    """
    from conductor.billing import SUBSCRIPTION_LABEL, AggregateBilling

    fields = _safe_fields(observed.fields)

    def fail(outcome: Outcome) -> NoReturn:
        raise HarnessFailure(outcome, extra=fields)

    completed = [e for e in observed.events if _event_type(e) == "agent_completed"]
    if observed.exception is not None or not completed:
        fail(Outcome.INCONCLUSIVE)
    answer = (observed.output or {}).get("answer")
    if not isinstance(answer, str) or not answer.strip():
        fail(Outcome.OUTPUT_MISSING)
    if _event_data(completed[-1]).get("billing_mode") != "subscription":
        fail(Outcome.BILLING_NOT_SUBSCRIPTION)
    fields["billing_mode"] = "subscription"
    billing = AggregateBilling.from_wire((observed.usage or {}).get("billing"))
    if billing is None or billing.state != "subscription":
        fail(Outcome.BILLING_AGGREGATE_MISMATCH)
    fields["billing_state"] = "subscription"
    fields["requested_model"] = requested_model
    fields["effective_model"] = check_effective_model(observed.effective_model)
    fields["est_cost_usd"] = check_priced(observed.total_cost_usd)
    if SUBSCRIPTION_LABEL not in observed.console_text:
        fail(Outcome.BILLING_LABEL_MISSING)
    fields["billing_label_seen"] = True
    return fields


def _inference_runner(
    adapters: AdapterSet,
    variants: Mapping[Case, CaseVariant],
    canary: str,
    requested_model: str,
) -> Callable[[Case], Awaitable[CaseOutcome | Outcome]]:
    async def run(case: Case) -> CaseOutcome | Outcome:
        variant = variants[case]
        with adapters.observer.observing() as sink:
            observed = await adapters.workflow.execute(variant)
        # Scan first, also when the execution raised or timed out (the adapter returns an
        # observation for those).  A leak or an incomplete scan is recorded on the case's
        # findings; the case wrapper ranks it above the outcome computed below.
        adapters.board.for_case(case).record_streams(canary, observed.streams)
        chain = exception_chain(observed.exception)
        fields = _safe_fields(observed.fields)
        if observed.exception is not None:
            fields["exception_class"] = exception_class_of(observed.exception)
        if case is Case.L3:
            fields["requested_model"] = requested_model
            return CaseOutcome(classify_l3(sink, chain, observed.events), fields)
        if case is Case.L2 and any(o.assistant_error == "authentication_failed" for o in sink):
            raise HarnessFailure(Outcome.CANARY_USED_IN_L2, extra=fields)
        return CaseOutcome(
            Outcome.OK,
            assert_inference_success(dataclasses.replace(observed, fields=fields), requested_model),
        )

    return run


def build_case_runners(
    adapters: AdapterSet | None,
    *,
    variants: Mapping[Case, CaseVariant],
    canary: str,
    requested_model: str,
) -> dict[Case, CaseRunner]:
    """Compose the four case runners from the adapter seams (fail closed if none are supplied)."""
    if adapters is None:

        async def unwired(case: Case) -> CaseOutcome | Outcome:
            raise HarnessFailure(Outcome.ADAPTERS_NOT_WIRED)

        return dict.fromkeys(ORDER, unwired)
    inference = _inference_runner(adapters, variants, canary, requested_model)
    return {
        Case.L0: _l0_runner(adapters, canary),
        Case.L1: inference,
        Case.L3: inference,
        Case.L2: inference,
    }


def _default_emit(config: Any) -> Callable[[dict[str, object]], None]:
    """Hand records to the evidence plugin: per-case and session records as they come, and the
    one run-level record (no ``case`` key) through :meth:`ZeroSkipPlugin.hand_over` (Path A),
    which refuses a second one."""
    plugin = config.pluginmanager.get_plugin(ZERO_SKIP_PLUGIN_NAME)

    def emit(record: dict[str, object]) -> None:
        line = emit_evidence(record)  # validates, also without a plugin
        if plugin is None:
            return
        if "case" in record:
            plugin.evidence_lines.append(line)
        else:
            plugin.hand_over(record)

    return emit


def _default_marker(config: Any) -> Callable[[str], None]:
    """Report the fixed ``evidence_fallback_failed: <case>`` line through the evidence channel."""
    plugin = config.pluginmanager.get_plugin(ZERO_SKIP_PLUGIN_NAME)

    def mark(line: str) -> None:
        if plugin is not None and re.fullmatch(rf"evidence_fallback_failed: (?:{_CASE_ALT})", line):
            plugin.evidence_lines.append(line)

    return mark


def environment_facts() -> dict[str, object]:
    """Date, host, interpreter and SDK version for the session record (no subprocess)."""
    import datetime
    import importlib.metadata
    import platform

    try:
        sdk_version = importlib.metadata.version("claude-agent-sdk")
    except importlib.metadata.PackageNotFoundError:
        sdk_version = "unknown"
    return {
        "date_utc": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host_os": platform.system() or "unknown",
        "python_version": platform.python_version(),
        "sdk_version": sdk_version,
    }


async def run_official_session(
    config: Any,
    tmp_path: Path,
    adapters: AdapterSet | None,
    *,
    readiness_check: Callable[[], None] = assert_real_readiness,
    prereq_check: Callable[[], str] = check_prerequisites,
    quota: QuotaCounter | None = None,
    emit: Callable[[dict[str, object]], None] | None = None,
    canary: str | None = None,
    yaml_text: str | None = None,
    environ: Mapping[str, str] | None = None,
    read_table: Callable[[], Mapping[int, tuple[int, str]]] | None = None,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    grace_s: float = 10.0,
    git_state: Callable[[], tuple[str, bool]] | None = None,
    facts: Callable[[], dict[str, object]] = environment_facts,
    mark: Callable[[str], None] | None = None,
) -> SessionResult:
    """L0 -> L1 -> L3 -> L2 through the state machine; preflight failures run no case."""
    require_live_optin(config)
    assert_live_isolation(tmp_path)
    sink = emit or _default_emit(config)
    if mark is None and emit is None:
        mark = _default_marker(config)
    counter = quota or QuotaCounter()
    secret = canary or make_canary()
    board = adapters.board if adapters is not None else FindingsBoard(secret)
    if board.canary is None:
        board.canary = secret
    text = yaml_text if yaml_text is not None else EXAMPLE_PATH.read_text()
    try:
        requested = validate_model(os.environ.get(MODEL_ENV))
    except HarnessFailure:
        requested = DEFAULT_MODEL  # the preflight reports the invalid override
    variants = build_variants(
        text, secret, os.environ if environ is None else environ, model=requested
    )
    session_records: list[dict[str, object]] = []
    tree: dict[str, bool] = {"dirty": True}  # official evidence requires a clean tree (D12)

    def preflight() -> None:
        common_preflight(
            config, tmp_path, readiness_check=readiness_check, prereq_check=prereq_check
        )
        if adapters is not None:
            cli = adapters.cli.resolve()
            sha, tree["dirty"] = (git_state or (lambda: read_git_state(config, tmp_path)))()
            record = evidence(
                case="session",
                **facts(),
                git_sha=sha,
                git_dirty=tree["dirty"],
                source_tree_verdict="verified",
                cli_class=cli.cli_class,
                cli_version=cli.version,
                isolation_verdict="isolated",
            )
            session_records.append(record)
            sink(record)

    runners = _protected_runners(
        config,
        tmp_path,
        adapters,
        build_case_runners(adapters, variants=variants, canary=secret, requested_model=requested),
        read_table=read_table,
        sleep=sleep,
        grace_s=grace_s,
        board=board,
    )
    hooks = {
        Case.L3: lambda: assert_config_paired(variants[Case.L3], variants[Case.L2]),
        Case.L2: lambda: assert_env_paired(variants[Case.L3], variants[Case.L2]),
    }
    result = await run_session(
        preflight=preflight,
        runners=runners,
        quota=counter,
        emit=sink,
        pre_hooks=hooks,
        board=board,
        mark=mark,
    )
    result.evidence[:0] = session_records
    sink(run_level_record(result))
    plugin = config.pluginmanager.get_plugin(ZERO_SKIP_PLUGIN_NAME)
    if plugin is not None:
        case_records = [r for r in result.evidence if r.get("case") in _REAL_CASES]
        plugin.ordered_test_passed = result.succeeded
        plugin.git_dirty = tree["dirty"]
        plugin.canary_scans_complete = bool(case_records) and all(
            scan_is_clean_and_complete(r.get("canary_scan"), r.get("case")) for r in case_records
        )
    return result


def _guarded(config: Any, tmp_path: Path, runner: CaseRunner) -> CaseRunner:
    async def guarded(case: Case) -> CaseOutcome | Outcome:
        return await run_case(config, tmp_path, case, runner)

    return guarded


def _protected_runners(
    config: Any,
    tmp_path: Path,
    adapters: AdapterSet | None,
    runners: Mapping[Case, CaseRunner],
    *,
    read_table: Callable[[], Mapping[int, tuple[int, str]]] | None,
    sleep: Callable[[float], Awaitable[object]],
    grace_s: float,
    board: FindingsBoard | None = None,
) -> dict[Case, CaseRunner]:
    """Gate + isolation guard on every runner, and the descendant check when adapters exist."""
    if adapters is None:
        return {case: _guarded(config, tmp_path, r) for case, r in runners.items()}
    table_reader = read_table or adapters.descendants.snapshot
    return {
        case: with_descendant_check(
            _guarded(config, tmp_path, runner),
            read_table=table_reader,
            root_pid=os.getpid(),
            board=board if board is not None else adapters.board,
            sleep=sleep,
            grace_s=grace_s,
        )
        for case, runner in runners.items()
    }


async def probe_readiness(
    config: Any,
    tmp_path: Path,
    adapters: AdapterSet | None,
    *,
    readiness_check: Callable[[], None] = assert_real_readiness,
    prereq_check: Callable[[], str] = check_prerequisites,
    emit: Callable[[dict[str, object]], None] | None = None,
    read_table: Callable[[], Mapping[int, tuple[int, str]]] | None = None,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    grace_s: float = 10.0,
    canary: str | None = None,
    mark: Callable[[str], None] | None = None,
) -> SessionResult:
    """L0 alone (the readiness-only check): not official evidence."""
    require_live_optin(config)
    assert_live_isolation(tmp_path)
    sink = emit or _default_emit(config)
    if mark is None and emit is None:
        mark = _default_marker(config)
    secret = canary or make_canary()
    board = adapters.board if adapters is not None else FindingsBoard(secret)
    if board.canary is None:
        board.canary = secret
    runners = build_case_runners(adapters, variants={}, canary=secret, requested_model="")

    def preflight() -> None:
        common_preflight(
            config, tmp_path, readiness_check=readiness_check, prereq_check=prereq_check
        )

    protected = _protected_runners(
        config,
        tmp_path,
        adapters,
        {Case.L0: runners[Case.L0]},
        read_table=read_table,
        sleep=sleep,
        grace_s=grace_s,
        board=board,
    )
    result = await run_session(
        preflight=preflight,
        runners=protected,
        quota=QuotaCounter(),
        emit=sink,
        cases=(Case.L0,),
        board=board,
        mark=mark,
    )
    sink(run_level_record(result))
    return result


def resolve_cli_evidence(
    config: Any,
    tmp_path: Path,
    *,
    find_cli: Callable[[], Path | None] | None = None,
    run: Callable[[Sequence[str]], str] | None = None,
) -> CliEvidence:
    require_live_optin(config)
    assert_live_isolation(tmp_path)
    cli_class = check_prerequisites(find_cli=find_cli)
    if find_cli is None:
        from conductor.providers.claude_agent_sdk import _find_claude_cli

        find_cli = _find_claude_cli
    cli = find_cli()
    assert cli is not None
    return CliEvidence(cli_class, read_cli_version(config, tmp_path, cli, run=run))


def read_cli_version(
    config: Any,
    tmp_path: Path,
    cli: Path,
    *,
    run: Callable[[Sequence[str]], str] | None = None,
) -> str:
    require_live_optin(config)
    assert_live_isolation(tmp_path)

    def _default(argv: Sequence[str]) -> str:
        return _run_owned_subprocess(argv, timeout=10.0)[1]

    try:
        return parse_cli_version((run or _default)([str(cli), "--version"]))
    except (OSError, subprocess.SubprocessError) as exc:
        raise HarnessFailure(Outcome.PREREQ_CLI_MISSING) from exc


# ============================================================================
# The live tests
# ============================================================================

_TEST_MODULE: Final = "tests/test_integration/test_claude_agent_sdk_subscription_real.py"
PIPEFAIL_LINE: Final = "set -o pipefail"

# The seven inherited variables that can put unvetted lines into a capture.  The ``env -u`` prefix
# removes them from the one pytest process only; the operator's shell is not modified.
UNSET_VARIABLES: Final = (
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "PYTEST_DEBUG",
    "PYTHONWARNINGS",
    "PYTHONDEVMODE",
    "PYTHONVERBOSE",
    "PYTHONPROFILEIMPORTTIME",
)
ENV_UNSET_PREFIX: Final = "env " + " ".join(f"-u {name}" for name in UNSET_VARIABLES)
EVIDENCE_PYTEST_FLAGS: Final = (
    "-q --color=no --show-capture=no --disable-warnings --tb=no -rN -p no:cacheprovider"
)


def _evidence_command(selector: str) -> str:
    """The one authorized command form: gates on one command, deliberate output only.

    The seven-variable ``env -u`` prefix removes inherited pytest and Python settings for this one
    process.  ``-q`` removes the ``rootdir:`` and ``plugins:`` header, ``--color=no`` every ANSI
    sequence, ``--show-capture=no`` every captured stdout / stderr / log section, ``--disable-
    warnings`` the warnings summary, ``--tb=no`` every traceback, source line and message, ``-rN``
    the short test summary and ``-p no:cacheprovider`` the repository cache.  ``-rA`` and ``-s``
    are absent, and ``PYTEST_DISABLE_PLUGIN_AUTOLOAD`` is deliberately not set (so the offline
    proofs and a live run use the same plugin set).  ``2>&1 | tee`` writes stdout and stderr to a
    path outside the repository, under ``pipefail`` so a failing status is not hidden.  Failure and
    interrupt rendering after the report sanitizer registers is fixed text
    (:class:`ReportSanitizer`).
    """
    return (
        f"{ENV_UNSET_PREFIX} \\\n"
        f'  {GATE_ENV}=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" \\\n'
        '  "$PY" -m pytest -m real_api \\\n'
        f"  {_TEST_MODULE} \\\n"
        f'  -k {selector} {EVIDENCE_PYTEST_FLAGS} 2>&1 | tee "$EVIDENCE_FILE"'
    )


READINESS_ONLY_COMMAND: Final = _evidence_command("readiness_probe_only")
OFFICIAL_COMMAND: Final = _evidence_command("official_live_evidence")

# The operator shell gate (Bash or Zsh, run as a script file; not generic POSIX ``sh``: under dash
# ``set -o pipefail`` is a fatal error).  Each readiness or live operation is run from its own
# script invocation, with its own fresh ``$EVIDENCE_FILE`` and ``EXPECTED`` (``readiness_only``
# for the readiness-only check, ``official`` for the official live validation).
PRE_GATE: Final = """\
set -o pipefail                                                    # Bash or Zsh
: "${EXPECTED:?}"                                                  # readiness_only or official
if env | grep -E '^(CLAUDE_|ANTHROPIC_)' >/dev/null 2>&1; then exit 1; fi   # plain terminal
[ ! -e "$EVIDENCE_FILE" ] && [ ! -L "$EVIDENCE_FILE" ] || exit 1   # no pre-existing path
: > "$EVIDENCE_FILE" || exit 1                                     # the path can be created
"""
PIPELINE_STATUS_LINE: Final = (
    "PIPELINE_STATUS=$?   # the very first command after the pipeline; the pipeline status under "
    "pipefail, not necessarily pytest's own"
)
# ``-I`` ignores every ``PYTHON*`` variable, the user site and the script directory (a shadowing
# ``json.py`` or ``re.py`` or a startup variable cannot change the verdict); ``-S`` prevents
# ``site`` (no ``.pth`` file, ``sitecustomize`` or ``usercustomize``); ``-B`` writes no bytecode.
CLASSIFIER_FLAGS: Final = ("-I", "-S", "-B")
CLASSIFY_BLOCK: Final = (
    """\
VERDICT=$(
  "$PY" """
    + " ".join(CLASSIFIER_FLAGS)
    + """ tests/test_integration/test_claude_agent_sdk_subscription_real.py \\
    --check-capture "$EVIDENCE_FILE" \\
    --pipeline-status "$PIPELINE_STATUS" \\
    2>/dev/null
)
CLASSIFY_STATUS=$?
"""
)
MATRIX_BLOCK: Final = """\
: "${EXPECTED:?}"                                                  # an empty token must never match
case "$CLASSIFY_STATUS:$VERDICT" in
  "0:$EXPECTED")
    echo "classified: $EXPECTED"                                   # a candidate; approves nothing
    exit 0 ;;
  "3:failure_record")
    echo "classified: failure_record (kept; authorizes nothing)"
    exit 3 ;;                                                    # kept, yet never a success
  *)
    printf '%s\\n' "$VERDICT" | grep -E '^discard [a-z_]{1,40}$'     # a closed-set code
    rm -f -- "$EVIDENCE_FILE"
    echo "capture deleted; stop"
    exit 1 ;;
esac
"""


def test_readiness_probe_only(
    pytestconfig: pytest.Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """L0 alone: the readiness-only check.  Not official evidence.

    ``capfd`` is requested without ``capsys``: pytest refuses both in one test, and ``capfd``
    also captures ``sys.stdout`` / ``sys.stderr`` writes.
    """
    canary = make_canary()
    try:
        adapters = configured_adapters(pytestconfig, tmp_path, monkeypatch, capfd, canary=canary)
        result = asyncio.run(probe_readiness(pytestconfig, tmp_path, adapters, canary=canary))
    except HarnessFailure as exc:
        fail_closed(exc, pytestconfig)
    finalize(result)


def test_official_live_evidence(
    pytestconfig: pytest.Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """L0 -> L1 -> L3 -> L2 in one function: the only way to guarantee order and shared state."""
    canary = make_canary()
    try:
        adapters = configured_adapters(pytestconfig, tmp_path, monkeypatch, capfd, canary=canary)
        result = asyncio.run(run_official_session(pytestconfig, tmp_path, adapters, canary=canary))
    except HarnessFailure as exc:
        fail_closed(exc, pytestconfig)
    finalize(result)


def iter_public_process_helpers() -> Iterator[str]:
    """Names of the helpers that must enforce the gate and isolation as their first statements."""
    yield from (
        "resolve_cli_evidence",
        "read_cli_version",
        "descendant_snapshot",
        "read_git_state",
        "run_case",
        "probe_readiness",
        "run_official_session",
        "common_preflight",
    )


def iter_adapter_process_methods() -> Iterator[tuple[str, str]]:
    """``(class, method)`` of every real-adapter entry point that must guard itself first."""
    yield from (
        ("RealReadinessAdapter", "probe"),
        ("RealWorkflowAdapter", "execute"),
        ("RealObserverInstaller", "observing"),
        ("RealDescendantAdapter", "snapshot"),
        ("RealCliEvidenceAdapter", "resolve"),
    )
