# Claude Subscription Billing Mode

**Status: experimental.** The `claude-agent-sdk` provider remains experimental (see
[Experimental Providers](experimental.md)). This page is the operator runbook for using it with a
Claude subscription login, and for the maintainer-only live validation harness.

**No passing official evidence exists yet. The readiness-only check passed once during development.
The first official validation attempt was retained as a non-official failure record, which authorizes
nothing. Any future readiness or official operation requires fresh explicit human approval, and no
retry is ever automatic.** Every *live-proven* cell in the [status table](#status-table) reads
*not yet*. Nothing on this page claims that a real Claude CLI, login or inference has been exercised
by the automated harness.

## What this is, and what it is not

- The provider delegates authentication to the `claude` CLI and your local Claude login.
  Conductor does not store, print or log credentials.
- Dollar figures shown for subscription runs are **API-equivalent estimates** computed from token
  counts at API rates. They are **not** invoices, charges or quota. Conductor does not measure
  subscription quota.
- The live validation harness is **POSIX-only** (macOS or Linux).
- This page describes only behavior that exists in the code. Where a behavior has been exercised
  only against test doubles, or not at all, it is marked in the [status table](#status-table).

## Log in safely

1. Run `claude auth login` yourself, in a terminal, in the same operating-system user session that
   will run Conductor. Neither Conductor nor its tests ever run `claude auth login` or
   `claude auth logout`.
2. Do not put credentials in workflow YAML, and start from a shell that has none of
   `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN` set.
3. The `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX` and `CLAUDE_CODE_USE_FOUNDRY` selectors
   must be unset: an explicit `auth_mode` refuses to run while one is inherited.

## Verify readiness

```bash
conductor doctor providers --provider claude-agent-sdk --check
```

This runs the provider's readiness check, which invokes `claude auth status --json` once under the
default `auto` mode (no API key, no inference). It is separate from the live harness and needs its
own approval when run by a maintainer. Raw CLI output is never printed by Conductor.

## Configure explicit subscription mode

`examples/claude-agent-sdk-subscription.yaml` is the shipped minimal workflow:

```yaml
workflow:
  runtime:
    provider:
      name: claude-agent-sdk
      auth_mode: subscription
      native_tools: none
      setting_sources: []
    default_model: claude-haiku-4-5
    max_session_seconds: 60
```

Its agent has `tools: []`, no `retry:` block and one structured output, `answer`. Validate it
without running it:

```bash
conductor validate examples/claude-agent-sdk-subscription.yaml
```

`auth_mode: subscription` refuses to run while a cloud-backend selector is inherited or while
`setting_sources` is non-empty, because a settings file can inject a credential after Conductor has
configured the child environment. `ANTHROPIC_BASE_URL`, custom headers and proxies are **not**
neutralized by an explicit mode; they make the billing source `unknown`.

## Run the minimal example

This is ordinary product use: it makes **one real inference** on your subscription and writes run
records to the normal `~/.conductor/runs`.

```bash
conductor run examples/claude-agent-sdk-subscription.yaml --input question="What is Conductor?"
```

The automated harness below does **not** exercise this entry point.

## Read the labels

For a priced model on a subscription login, the usage summary shows the total with a label and a
note (format taken from the code, with a placeholder amount; *illustrative, not the output of a
real run*):

```text
Total: $<amount> (API-equivalent estimate)
Estimated at API rates from token counts; not an invoice or an additional charge.
```

- The label is printed only when the total cost is greater than zero. For an unpriced model the
  summary says `Cost data unavailable (unknown model pricing)` instead, and no label appears.
- The label describes the *estimate*. It does not tell you what, if anything, was charged.

## Troubleshooting

Each entry is keyed on a message the code can produce.

| Message | Meaning |
|---|---|
| `Not logged in to Claude Code. Run: claude auth login` | The CLI reported no login. Log in as described above. |
| `Authentication check timed out. Claude CLI may not be accessible or credential store may be blocked.` | The status probe did not finish in 5 seconds. A credential-store (Keychain) prompt may be waiting for a person. |
| `The process running Conductor cannot access the Claude Code login context (keychain/credential store unavailable)…` | Run Conductor in the same user session as your Claude Code login. |
| `Authentication check failed. Claude CLI may not be accessible or the login context is unavailable.` | The probe exited non-zero without a readable status. |
| `Claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code` | No usable CLI was resolved. |
| `auth_mode '<mode>' cannot be used while <NAME> is set in the inherited environment…` | A cloud-backend selector is set. Unset it, or use `auth_mode: auto`. |
| `auth_mode '<mode>' cannot be combined with runtime.provider.setting_sources (…)` | Remove `setting_sources`, or use `auth_mode: auto`. |
| `auth_mode=<mode>: blanking inherited <NAMES> for the Claude child process.` | A warning: the named credential variables were set and were blanked for the child. |
| `exceeded maximum session duration` | The session hit `max_session_seconds`. |

## Status table

*Implemented* means the code exists. *Hermetically tested* means the offline test suite covers it
with test doubles and no real CLI, login or network. *Live-proven* means it was observed against a
real Claude CLI and login: **nothing is live-proven yet**. *Unverified* lists what only a real run
can settle.

| Capability | Implemented | Hermetically tested | Live-proven | Unverified |
|---|---|---|---|---|
| `auth_mode` resolution and env blanking | yes | yes | *not yet* | live blanking (L2) |
| Readiness (`claude auth status --json`) | yes | yes (fixtures) | *not yet* | real field values (L0) |
| `billing_mode == subscription` derivation | yes | yes (fixtures) | *not yet* | the `"firstParty"` constant; `subscriptionType` presence |
| `API-equivalent estimate` label | yes | yes | *not yet* | real console output |
| `auto` + API key gives `metered_api` | yes (by construction) | yes | *not yet* (the harness tests an *invalid* key only) | that a valid key wins |
| Cloud-selector / `setting_sources` refusal | yes | yes | not applicable | managed / enterprise settings |
| Hard session timeout / interrupt | yes | yes | not in this PR | real-CLI timing |
| Bundled CLI reads the user's login | none | no | *not yet* (L0, L1) | cross-version compatibility |
| `conductor run` on a real login | yes | yes (mocked) | *manual step only* | none |
| Live harness (L0, L1, L3, L2) | yes | yes (all boundaries replaced) | *not yet* | every real-CLI behavior above |

The *live-proven* column changes only from official evidence, never from expectation. No passing
official evidence exists yet. The readiness-only check passed once during development. The first
official validation attempt was retained as a non-official failure record, which authorizes nothing.
Any future readiness or official operation requires fresh explicit human approval, and no retry is
ever automatic.

## Live validation (maintainers)

The harness is `tests/test_integration/test_claude_agent_sdk_subscription_real.py`, with its offline
safety tests in `tests/test_config/test_claude_subscription_real_gate.py`. It is experimental,
POSIX-only and never runs in CI, on untrusted pull requests or on shared accounts.

There are two live operations. No passing official evidence exists yet. The readiness-only check
passed once during development. The first official validation attempt was retained as a non-official
failure record, which authorizes nothing. Any future readiness or official operation requires fresh
explicit human approval, and no retry is ever automatic. The two operations are:

- the **readiness-only check** (`-k readiness_probe_only`) runs case L0 alone. It makes **one**
  authentication probe and no inference. It is **not official end-to-end evidence**.
- the **official live validation** (`-k official_live_evidence`) runs L0, L1, L3 and L2 in one
  ordered test. It makes **five** authentication probes and at most three inference-capable
  attempts.

The **optional manual example** is a separate, separately approved step: one ordinary
`conductor run` of the shipped example (see [Run the minimal example](#run-the-minimal-example)).

### The two gates

The live tests run only when **both** are supplied to the **same command**:

1. `-m real_api` (the marker is shared with other providers' real-API tests, so it alone never
   spends anything here), and
2. `CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION=1`, the exact value `1`.

**Never `export` the variable.** Use it only as a prefix on one command. Never put it in a shell
profile, `.envrc`, an IDE run configuration, `pyproject.toml`, a workflow file or a CI secret, and
never leave it set between commands. Once both gates are supplied, an unmet prerequisite is a
**failure**, never a skip; a run with any skipped test is failed by the session-wide zero-skip
check. An xdist worker is refused. The harness also refuses to run unless the repository's test
isolation fixtures are active, so run/event/PID directories stay under the test's temporary
directory.

### Before either operation

1. Commit the change under test. The official live validation must run on a
   **clean committed tree**: `git status --porcelain` prints nothing.
   **Untracked files make the tree dirty.** On a dirty tree the run still executes, reports
   `official: false`, and has spent subscription usage for evidence that cannot be used.
2. The tested Git SHA is recorded in the evidence (`git_sha`, with `git_dirty`), so a result maps to
   exactly one commit. The readiness-only check does not read the Git state and could run on a
   dirty tree; run it after the commit anyway, so that its evidence maps to a SHA.
3. Use an interpreter that already has the project dependencies. No command on this page installs
   or synchronizes anything. `uv run` and `make` targets are not used because they may synchronize
   an environment.

### A human must be present

Each authentication probe may read or refresh authentication state, contact Anthropic services or
raise a Keychain prompt, which may surface as `Authentication check timed out`. A person must be at
the machine throughout **both** the readiness-only check and the official live validation.

### Commands

No passing official evidence exists yet. The readiness-only check passed once during development. The
first official validation attempt was retained as a non-official failure record, which authorizes
nothing. Any future readiness or official operation requires fresh explicit human approval, and no
retry is ever automatic.

Run both operations in **Bash or Zsh** (zsh on macOS, bash on Linux), from a **plain terminal
session**, never from inside a Claude Code session shell or another agent shell. Write the steps
below as a script file so that `exit` stops it, and run **each readiness or live operation from its
own script invocation**, with its own fresh `EVIDENCE_FILE` and its own `EXPECTED`. The sequence is
**not** generic POSIX `sh`: under dash `set -o pipefail` is a fatal error, which fails loudly.

`PY` is the interpreter and `EVIDENCE_FILE` a file path **outside the repository** that does not
exist yet. The gate variable is a prefix on one command (an `env` argument) and is never exported.
`EXPECTED` is `readiness_only` for the readiness-only check and `official` for the official live
validation; the sequence refuses to start when it is unset or empty.

The sequence for each operation is: the **pre-gate**, the pytest command through `2>&1 | tee`, the
saved `PIPELINE_STATUS`, the hardened classifier and the status/token matrix.

```bash
PY=<an interpreter that already has the project dependencies>
EVIDENCE_FILE=<a new file path outside this repository>
EXPECTED=readiness_only

# pre-gate: it stops before any live action if any check fails
set -o pipefail                                                    # Bash or Zsh
: "${EXPECTED:?}"                                                  # readiness_only or official
if env | grep -E '^(CLAUDE_|ANTHROPIC_)' >/dev/null 2>&1; then exit 1; fi   # plain terminal
[ ! -e "$EVIDENCE_FILE" ] && [ ! -L "$EVIDENCE_FILE" ] || exit 1   # no pre-existing path
: > "$EVIDENCE_FILE" || exit 1                                     # the path can be created
# readiness-only check (case L0; not official evidence)
env -u PYTEST_ADDOPTS -u PYTEST_PLUGINS -u PYTEST_DEBUG -u PYTHONWARNINGS -u PYTHONDEVMODE -u PYTHONVERBOSE -u PYTHONPROFILEIMPORTTIME \
  CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" \
  "$PY" -m pytest -m real_api \
  tests/test_integration/test_claude_agent_sdk_subscription_real.py \
  -k readiness_probe_only -q --color=no --show-capture=no --disable-warnings --tb=no -rN -p no:cacheprovider 2>&1 | tee "$EVIDENCE_FILE"
PIPELINE_STATUS=$?   # the very first command after the pipeline; the pipeline status under pipefail, not necessarily pytest's own

# classification (offline, no gate): the hardened classifier, then the closed matrix
VERDICT=$(
  "$PY" -I -S -B tests/test_integration/test_claude_agent_sdk_subscription_real.py \
    --check-capture "$EVIDENCE_FILE" \
    --pipeline-status "$PIPELINE_STATUS" \
    2>/dev/null
)
CLASSIFY_STATUS=$?
: "${EXPECTED:?}"                                                  # an empty token must never match
case "$CLASSIFY_STATUS:$VERDICT" in
  "0:$EXPECTED")
    echo "classified: $EXPECTED"                                   # a candidate; approves nothing
    exit 0 ;;
  "3:failure_record")
    echo "classified: failure_record (kept; authorizes nothing)"
    exit 3 ;;                                                    # kept, yet never a success
  *)
    printf '%s\n' "$VERDICT" | grep -E '^discard [a-z_]{1,40}$'     # a closed-set code
    rm -f -- "$EVIDENCE_FILE"
    echo "capture deleted; stop"
    exit 1 ;;
esac
```

For the official live validation, run a **separate script** with `EXPECTED=official`, a fresh
`EVIDENCE_FILE` and the same pre-gate, classifier and matrix around this command, on the same clean
commit:

```bash
# official live validation (L0, L1, L3, L2)
env -u PYTEST_ADDOPTS -u PYTEST_PLUGINS -u PYTEST_DEBUG -u PYTHONWARNINGS -u PYTHONDEVMODE -u PYTHONVERBOSE -u PYTHONPROFILEIMPORTTIME \
  CONDUCTOR_REAL_CLAUDE_SUBSCRIPTION=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" \
  "$PY" -m pytest -m real_api \
  tests/test_integration/test_claude_agent_sdk_subscription_real.py \
  -k official_live_evidence -q --color=no --show-capture=no --disable-warnings --tb=no -rN -p no:cacheprovider 2>&1 | tee "$EVIDENCE_FILE"
```

Select one test or the other, never both. Add `-n 0` only if the environment has xdist.

What the command is built from:

- The **seven unset operations** `env -u PYTEST_ADDOPTS -u PYTEST_PLUGINS -u PYTEST_DEBUG -u
  PYTHONWARNINGS -u PYTHONDEVMODE -u PYTHONVERBOSE -u PYTHONPROFILEIMPORTTIME` remove inherited
  pytest options, plugins, debug output, warning filters, dev mode and import tracing from that one
  process only; your shell is not modified. `PYTEST_DISABLE_PLUGIN_AUTOLOAD` is deliberately **not**
  set: plugin autoload stays on so that the offline proofs and a live run use the same plugin set,
  and an unexpected plugin's output makes the classifier discard the capture.
- `-q` removes pytest's `rootdir:` and `plugins:` header (an absolute path and plugin names).
  `--color=no` removes every ANSI sequence, also when `FORCE_COLOR` or `PY_COLORS` is set.
- `--show-capture=no` hides every captured stdout, stderr and log section, even for a failing test.
  `-rA` and `-s` are deliberately **not** used: they print the capture sections of passing tests
  and turn capture off. Never add either.
- `--disable-warnings` hides the warnings summary, which `--show-capture=no` does not: a warning can
  carry provider text and an absolute path.
- `--tb=no` removes every traceback, source line and exception message, and `-rN` removes the short
  test summary (whose lines carry collection-error messages). No other `-r` option is used.
- `-p no:cacheprovider` keeps a pytest cache out of the repository.
- The evidence is written by a terminal-summary hook, so it appears without `-s`.
- `pipefail` keeps a failing exit status visible through the pipe; without it `tee` reports success
  for a failed or interrupted run.

**The shell gate.** `PIPELINE_STATUS=$?` must be the **very next command** after the pipeline. It is
the **pipeline status under `pipefail`, not necessarily pytest's own status**: an unwritable `tee`
target gives 1 even when pytest returned 0 or 2. The classifier is run with `-I -S -B`: `-I` ignores
every `PYTHON*` variable, the user site and the script directory (a shadowing `json.py` or `re.py`,
or a startup variable, cannot change the verdict), `-S` prevents `site`, `.pth` files and
`sitecustomize`, and `-B` writes no bytecode. The matrix tests **both** the exit status and the exact
stdout token. It prints exactly one of `official` (exit 0), `readiness_only` (exit 0),
`failure_record` (exit 3) or `discard <code>` (exit 1), needs no gate and no environment variable,
echoes nothing and deletes nothing.

- Exit 0 with the **expected** token makes the capture a **candidate**: eligible for review, and it
  approves nothing; the next live step still needs its own explicit approval.
- Exit 3 with `failure_record` is a sanitized failure or interruption record. It is **kept** locally
  at the path you chose outside the repository, for your own reading, and the script exits with
  status 3, so a caller can never mistake it for success. It is **never** shared,
  committed, quoted as successful evidence or used to authorize another step, and it never changes a
  documentation claim.
- **Every other combination** (exit 0 with unexpected stdout, the token of the other run kind, exit
  1 without an exact `discard <code>`, a classifier that failed to start, a `tee` failure, a stale
  path, a malformed status) **deletes the capture and stops**.
- A `tee` failure after a live command has run leaves **no valid capture**: usage may have been
  spent and pytest's own status is lost. Do not reuse the path; the pre-gate refuses an existing
  one.
- Never share, quote, commit or use a capture before the matrix has accepted it as a candidate.
  A capture is never judged by eye, and the evidence section alone is necessary, never sufficient.

**The plain terminal.** A Claude Code session shell carries `CLAUDE_CODE_*`, `CLAUDE_EFFORT`,
`CLAUDE_PID` and similar variables that every child process inherits. Nothing in the harness reads
them and they are **not accepted** as part of the evidence environment: the pre-gate refuses to
start when any `CLAUDE_*` or `ANTHROPIC_*` variable is present, prints no name or value, and the
`env -u` prefix does not scrub them (a silent scrub would make the evidence describe an environment
that did not exist). Keep your shell free of `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and
`CLAUDE_CODE_OAUTH_TOKEN`, as [Log in safely](#log-in-safely) says.

**The report sanitizer.** Under both gates a **gate-scoped report sanitizer** renders every failure
and interrupt from fixed text. Exception messages, contexts, causes, tracebacks, source lines,
fixture representations, warnings and absolute paths are **not saved**: a failed test shows only
`unexpected exception: <ClassName>` (or the bare `unexpected exception` for an unsafe class name),
or the fixed harness outcome text; after the evidence section an interrupt shows only the lines
below. Only the rendering changes: the original exception, the exit status and the control flow are
untouched. In a **validated** capture only fixed framework markers and validated `EVIDENCE` records
appear. The registration order inside the session fixture is: both gates, the inert terminal-reporter
lookup, the evidence plugin, then the sanitizer as the very next statement, then every other
prerequisite. If the installed pytest cannot support the sanitizer, the run stops with
`prereq_report_sanitizer_unavailable` before any live operation, and that failure **is** recorded,
because the evidence plugin is registered first.

**What the flags and the fixture cannot guarantee.** The no-path, no-secret guarantee applies to a
capture the classifier prints `official` or `readiness_only` for. It is not a claim about every byte
a failed process may write, and absolute paths can be written transiently by a failed run:

- A `conftest` import failure or a plugin-load failure happens before pytest has a terminal reporter,
  so neither the fixture nor the flags can sanitize it. Such a run is never official: its file has
  no `claude subscription live evidence` section.
- `prereq_terminalreporter_missing` and a failure to register the evidence plugin also leave no
  section. An interruption before a run-level record exists is discarded as `run_record_missing`.
- A failure or interrupt in the registration window between the evidence plugin and the sanitizer
  can leave a section followed by pytest's **default** rendering; the classifier rejects it.
- A terminal width far beyond the grammar's bounds (a `COLUMNS` value far above 500) fails closed.

A saved file **without the evidence section must be deleted**, and so must every capture for which
the classifier prints `discard`. It must **not be shared, committed, quoted as evidence or used to
authorize the next live step**. A failure before any case result (`isolation_fixtures_missing`,
`adapters_not_wired`, `prereq_report_sanitizer_unavailable` and the other prerequisites) **does**
leave a section with a fixed-enum `primary_failure`.

**The interrupt lines.** After the evidence section a `KeyboardInterrupt` shows exactly three lines,
in this order: pytest's separator banner (`!!! KeyboardInterrupt !!!`), `interrupted: details
withheld` and pytest's constant line `(to show a full traceback on KeyboardInterrupt use
--full-trace)`, then a fixed count line. **No other interrupt line is acceptable**, and pytest's
normal banner or location line is never accepted.

**pytest upgrades.** `pytest>=9.0.3` is not upper-pinned, and the interrupt hint and the count
lines are pytest constants. A pytest change to a fixed line makes the classifier discard the
capture, which fails closed. After **any** pytest upgrade, rerun the offline safety tests before
any live validation.

### Sequence

1. Commit the change and confirm the tree is clean, untracked files included.
2. Run the readiness-only check through the shell gate. Only a capture the classifier prints
   `readiness_only` for (exit 0) is reviewed, and the next step is approved, separately, only from
   such a capture; a `failure_record` is kept and approves nothing, and every other combination
   deletes the capture.
3. Run the official live validation on the **same clean commit**, through the shell gate with
   `EXPECTED=official`.
4. Review the sanitized evidence of an `official` capture **before changing any documentation
   claim**.
5. Documentation claims (the [status table](#status-table) and the sentence in
   [Experimental Providers](experimental.md)) change only after that review and explicit approval,
   in a **later commit**. Until then every live-proven cell reads *not yet*. The evidence records
   the tested SHA, so that later commit does not make the evidence circular.
6. If the evidence contradicts how billing is derived, stop and ask for a separate approval; any
   change to the derivation is a new commit and needs a new official live validation.

### What the official live validation does

The cases run in a fixed order and each one's route environment is scrubbed (every `ANTHROPIC_*`
variable, `CLAUDE_CODE_OAUTH_TOKEN` and the three cloud selectors are removed for that case only;
your real `HOME` is kept).

| Case | What runs | Passes only if |
|---|---|---|
| L0 | The provider is built as the factory builds it for `auth_mode: subscription`; the real readiness check runs; the real billing derivation runs. | Readiness succeeded; billing is `subscription` with reason `first_party_login`; `subscriptionType` is present and `apiKeySource` is absent; the `apiProvider` constant is `validated` or `unexercised` (a mismatch fails). |
| L1 | The shipped example, loaded with `load_config` and run through `ProviderRegistry` and `WorkflowEngine`. | Structured `answer` output; a real `agent_completed` event with `billing_mode == "subscription"`; aggregate billing state `subscription`; requested and effective model present; a non-zero estimated cost; the label appears in the real usage summary. |
| L3 | The same workflow with only `auth_mode: auto`, with an **invalid** canary `ANTHROPIC_API_KEY` set. | Classified `invalid_key` from typed SDK signals (never from message text). `fell_back_to_login`, `model_unavailable` and `inconclusive` all fail the run. |
| L2 | The same workflow and the same environment names as L3, with only `auth_mode: subscription`. Runs only after L3 is `invalid_key`. | The same conditions as L1, and the canary appears in no retained stream. |

The canary is generated per run, is never read from your environment and is never a real key.

### Authentication probes and quota

- **Probes.** In the current implementation the production path runs the readiness probe
  (`claude auth status --json`) once for L0, **twice** for each of L1 and L2 (once when the
  provider registry validates the provider, once when the agent executes) and not at all for L3
  (an `auto` run with an API key skips the probe). The readiness-only check is therefore **one**
  probe and the official live validation is **five** probes (1 + 2 + 0 + 2). Neither duplicate is
  avoided, because avoiding it would change normal product behavior. This count was observed with
  test doubles; the real CLI's behavior is unverified. The SDK's own transport can also run
  `<cli> --version`, and the harness runs it once for evidence. Probes are not inference.
- **Quota.** At most **three** potentially quota-consuming attempts are allowed (L1, L3, L2); a
  fourth is refused. The designed flow needs at most two. There is no `retry:` block, so retries
  cannot multiply attempts. The optional manual example adds one, for a total ceiling of four.
- **Cost figures** are API-equivalent estimates, never quota, invoices or charges.

### Reading the evidence

Evidence is printed as `EVIDENCE {json}` lines under a `claude subscription live evidence`
section of the terminal summary, in three kinds:

- one **session-facts** record (`case: "session"`) after the official path's preflight succeeded;
  the readiness-only check emits **none**;
- one **per-case** record for each case that ran (L0, L1, L3, L2, in that order), also for a failed,
  timed-out or interrupted case;
- exactly **one run-level** record (no `case` key), last. A failure that escapes before the ordered
  session returns (the opt-in gate, the isolation prerequisite, unwired adapters, an unavailable
  sanitizer) is recorded by `fail_closed` with `primary_failure: session:<enum>:<Class>`; every
  other outcome is recorded after the session returns; never both.

The run-level record carries `primary_failure` (`<prefix>:<enum>:<Class>`: the prefix is `session`
when no case was active and the case otherwise; the class may be `none`), `not_executed`
(`<case>:<value>,...` in case order, only for cases that have no record; a completed case is never
listed), `quota_attempts_total`, `quota_ceiling`, `pytest_version` and `plugins` (the sorted
distribution plugins, or `unavailable`). `skipped_reports`, `zero_skip_verdict` and `official` are
**not** record fields: they are the three lines written first under the section heading, and
`official: true` requires that the ordered test passed, that no test was skipped, that the Git
working tree was clean and that every case's canary scan was complete and clean. A run that was
interrupted before any run-level record exists is discarded as `run_record_missing`.

Each case record carries:

- `outcome`, the primary outcome, and `adapter_outcome`, what the case itself produced. When a
  safety finding outranks the case, they differ.
- `secondary_findings`, drawn only from `canary_leak` and `descendant_leak`. The precedence is
  `canary_leak`, then `descendant_leak`, then an incomplete scan, then the case's own outcome; both
  leaks are always recorded.
- `interrupted`: `none`, `keyboard_interrupt`, `cancelled` or `other_base_exception`, and, for an
  interrupted case only, `exception_class`: the ASCII class name, or `unknown_exception`.
- `cleanup_failed`: a bounded, fixed list drawn only from `descendants` and `evidence`, in that
  order and never repeated; present only when a real cleanup or evidence step failed. It never
  carries free text and never replaces the cancellation or hides a finding.
- `canary_scan`: exactly eight fixed entries of the form `<stream>:<clean|leak|not_available>`, in
  this order: `stdout_stderr`, `console`, `logs`, `exceptions`, `events`, `workflow_result`,
  `evidence`, `tmp_files`. It is emitted on success, failure, timeout and cancellation. The entries
  never contain matched text, a canary value or a path.

The eight streams are what each case scans for the canary:

- `stdout_stderr` is what pytest's file-descriptor capture saw on stdout and stderr.
- `logs` is a private buffer of the SDK's and the provider's log records only; it never reaches
  pytest's report handlers, and the root logger is never changed.
- `workflow_result` is the structured result the engine returned. The engine does not expose the
  provider's raw response, so that is not scanned separately.
- `not_available` is allowed only for `workflow_result` (no result), and for `console` and `events`
  in L0 (no engine); any other gap makes the scan incomplete.

**Cancellation.** An interrupt (Ctrl-C) or a cancellation is never turned into a test failure and
never continues to a later case. The harness scans, observes descendants, restores its patches and
records the findings as secondary evidence, then re-raises the original exception: a cancellation
remains the primary outcome while its terminal rendering is sanitized. If assembling the normal
record fails during a cancellation, a fallback record is built from the findings already collected
(never empty, never without `canary_scan`); if even that cannot be emitted, the only output is the
fixed line `evidence_fallback_failed: <case>`. The guarantee covers the harness's own steps: a
production cleanup exception raised while unwinding can still replace a `CancelledError`, and is
then rendered as `unexpected exception: <ClassName>`.

Only allowlisted fields are ever retained: versions, model names, environment variable **names**,
booleans, fixed outcome codes, token counts and estimated cost. Never retained: account identity,
raw `auth status` output, credential or canary values, the raw subscription type, home paths,
Keychain data, raw stdout/stderr, raw log text, exception arguments or matched text.

### Reading the L3 diagnostic fields

The L3 case record (the invalid-key case) may carry three closed-enum **diagnostic fields**:
`diag_provider_retryability`, `diag_assistant_error` and `diag_api_status`. They **only describe**
what the harness observed. They never classify, never change an outcome and never authorize a
step: `invalid_key` still requires typed, non-retryable authentication evidence from the
provider error and the observed signals, and message text is never used.

The three states are exact:

- `absent` (one field) means the harness collected the signal and saw nothing of that kind.
- `unavailable` (always all three fields) means the outcome was already fixed and the diagnostic
  collection or validation then failed.
- **Omission of all three fields** means L3 classification was never reached, or the capture
  predates the diagnostic fields. An omitted triple on a `failure_record` is **not itself proof**
  that classification was never reached: it may be a pre-amendment capture; it remains
  non-authorizing, and an `official` capture rejects omission (§5.8 item 9).

An `official` capture is accepted only if its L3 record carries a qualifying triple (a
non-retryable or `mixed` retryability **and** a typed 401) or the complete all-`unavailable`
triple; the check can only reject, never create an `official` verdict.

The table below is read on the record's **`adapter_outcome`** (what the unchanged classification
produced), **not** on `outcome`, which a canary or descendant finding can replace. `AO` is the
`adapter_outcome`, `R` is `diag_provider_retryability`, `A` is `diag_assistant_error` and `S` is
`diag_api_status`. `T` (typed 401) means `A = authentication_failed` or `S = "401"`. `Q` (the
gate's non-retryable condition) means `R ∈ {non_retryable, mixed}`. `X` (transient-looking signal)
means `A ∈ {rate_limit, server_error}` or `S ∈ {"429", 5xx}`. The state of the triple is **C**
(complete, valid, none `unavailable`), **U** (all three `unavailable`), **O** (omitted) or **M**
(present but neither C nor U). `K` is {`invalid_key`, `inconclusive`}. Rows 1 to 6 apply only to
`AO ∈ K` and state C; rows 7a to 7d are the complement. Every row ends with the same rule: **no
further run and no automatic retry**.

| Row | Predicate | Conclusion | Cannot be concluded | Next action |
|---|---|---|---|---|
| **1. Retryable error** | `AO = inconclusive ∧ C ∧ R = retryable ∧ ¬T` | the provider classified the failure as retry-eligible; `rate_limit` or `"429"` points to rate limiting, `server_error` or `5xx` to the provider side | whether an invalid key is rejected with a typed 401 | `environment_investigation` |
| **2. Non-retryable typed 401** | `AO = invalid_key ∧ C ∧ Q ∧ T` | the fake key was rejected with typed, non-retryable authentication evidence; for `mixed`, a qualifying non-retryable error existed **and** a retryable `ProviderError` was also observed in the same chain, and the conclusion holds for the non-retryable error only | a failure elsewhere in the capture; for `mixed`, which error ended the run | `read_failing_case` |
| **3. Non-retryable other 4xx** | `AO = inconclusive ∧ C ∧ R = non_retryable ∧ ¬T ∧ S ≠ "404" ∧ ¬X ∧ (S ∈ {"403", other_4xx} ∨ A ∈ {billing_error, invalid_request})` | the provider rejected the request non-retryably with a status or error the harness does not treat as authentication | whether the key was or was not the cause | `environment_investigation` |
| **4a. No typed signal (non-retryable)** | `AO = inconclusive ∧ C ∧ R = non_retryable ∧ ¬T ∧ S ≠ "404" ∧ ¬X ∧ S ∈ {absent, other} ∧ A ∈ {unknown, other, absent}` | the provider declared the failure non-retryable but no typed signal reached the observer | whether the key was rejected | `harness_investigation` |
| **4b. No `ProviderError`** | `AO = inconclusive ∧ C ∧ R = absent ∧ ¬T` | the failure was not a `ProviderError` (read `exception_class`) | whether the key was rejected | `environment_investigation` |
| **5a. Contradictory: retryable with a typed 401** | `AO = inconclusive ∧ C ∧ R = retryable ∧ T` | the observed signals do not describe one failure | which signal is the truth | `product_investigation_offline` |
| **5b. Contradictory: typed 401 without a `ProviderError`** | `AO = inconclusive ∧ C ∧ R = absent ∧ T` | the observation and the exception do not describe one failure | which signal is the truth | `harness_investigation` |
| **5c. Contradictory: mixed chain, no typed 401** | `AO = inconclusive ∧ C ∧ R = mixed ∧ ¬T ∧ S ≠ "404"` | the chain held both a retryable and a non-retryable `ProviderError` and no typed signal explains either | which error ended the run | `harness_investigation` |
| **5d. Contradictory: transient signal on a non-retryable error** | `AO = inconclusive ∧ C ∧ R = non_retryable ∧ ¬T ∧ S ≠ "404" ∧ X` | a non-retryable error carries a transient-looking signal | which signal is the truth | `harness_investigation` |
| **6a. Impossible: `invalid_key` without qualifying evidence** | `AO = invalid_key ∧ C ∧ ¬(Q ∧ T)` | the diagnostics and the unchanged classification disagree: a harness defect | the diagnostics never re-derive the outcome | `harness_defect_review` |
| **6b. Impossible: `inconclusive` with qualifying evidence** | `AO = inconclusive ∧ C ∧ Q ∧ T` | the classification would have returned `invalid_key`: a harness defect | as row 6a | `harness_defect_review` |
| **6c. Impossible: `inconclusive` with a 404 and no typed 401** | `AO = inconclusive ∧ C ∧ Q ∧ ¬T ∧ S = "404"` | the classification would have returned `model_unavailable`: a harness defect | as row 6a | `harness_defect_review` |
| **7a. Uninterpretable: another outcome** | `AO ∉ K` | nothing from this table | anything about the invalid-key result from the diagnostics | `no_diagnostic_reading` |
| **7b. Uninterpretable: diagnostics unavailable** | `AO ∈ K ∧ U` | the classification completed and the outcome stands; the collection or validation failed afterwards | anything the diagnostics would have said | `harness_investigation` |
| **7c. Uninterpretable: diagnostics omitted** | `AO ∈ K ∧ O` | classification was not reached on the diagnostic path, or the capture predates the diagnostic fields | anything from the diagnostics | `no_diagnostic_reading` |
| **7d. Uninterpretable: malformed triple** | `AO ∈ K ∧ M` | the triple is not valid; the offline classifier discards such a capture | anything | `harness_defect_review` |

Read `AO` first, then the state of the triple, then `R`, `T`, `S` and `A`, and always together
with `exception_class`, `elapsed_s`, `quota_attempts_total` and `interrupted`. A diagnostic reading
is a reason to investigate offline, never a reason to run again and never a reason to change the
classification. `uninterpretable` describes the evidence, not a verdict.

**The first official live validation.** Its capture is a **retained local failure record**: it is
never shared, committed, quoted as successful or official evidence or used to authorize another
step, it has no diagnostic fields and it receives no retroactive interpretation. The official live
validation has **not** passed, and nothing on this page calls that run a pass, a partial pass or
evidence of subscription inference.

**No step is ever retried automatically.** A new official live validation is considered only after
the offline correction is implemented, the full offline safety tests and the focused
falsification checks pass, an independent reviewer accepts it and it is committed on the same feature branch. It
then needs a **fresh, separate human approval** with the human present: the review, the commit and
this page do not imply it. Repeating the readiness-only check first is the human's separate
decision; nothing here requires or authorizes it.

### Descendant processes

After each case the harness looks for child processes of the test process that were not there
before, and reports them (PID and short name only). It **never signals** any discovered PID. A
verdict of `no_descendants_remaining` is deliberately narrow: it is **not** proof that nothing
leaked, because an orphan re-parented to PID 1 or a subreaper is invisible to a descendant walk and
PID reuse can hide a leaked PID.

### Side effects

A live run can update Claude-owned state under `~/.claude` and contact Anthropic services beyond
inference. No verified switch suppresses this, so none is set. The harness never reads, lists or
deletes anything under `~/.claude`.

### What stays unverified

- Whether the bundled CLI reads a login created by a different CLI version, and whether
  `claude auth status` performs a network call or raises a Keychain prompt.
- The real `apiProvider`, `subscriptionType` and `apiKeySource` values; the validated plan class
  would be one plan, one host and one date.
- How the CLI treats an invalid key under `auto`, and whether the typed signals the harness reads
  are emitted; without them L3 is `inconclusive`.
- That a **valid** API key wins over a login (this page makes no such claim).
- Managed or enterprise settings and `apiKeyHelper`.

### Offline safety tests

The offline safety tests need neither gate and start no CLI, network or inference:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" "$PY" -m pytest -p no:cacheprovider -q \
  tests/test_config/test_claude_subscription_real_gate.py \
  tests/test_integration/test_claude_agent_sdk_subscription_real.py \
  tests/test_integration/test_examples.py
```

The live module reports two skips in this command; those are the two gated live tests.
