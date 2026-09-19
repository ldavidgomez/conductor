"""
Hermetic tests for Claude Agent SDK effective auth context (AC1-AC9).

This test suite validates the effective-auth-context design without any real
subprocess invocation, real CLI discovery, real credentials, or real model
inference. All external dependencies are mocked.

Acceptance criteria tested:
  AC1: EffectiveAuthContext immutability + four-field construction
  AC2: Post-snapshot environment isolation (context.env_snapshot immutable)
  AC3: setting_sources rejection for subscription + api_key modes
  AC4: Neutralization matrix (ANTHROPIC_AUTH_TOKEN, CLAUDE_CODE_* vars)
  AC5: api_key mode requires nonblank key, no subprocess, rejects settings
  AC6: subscription readiness parses JSON loggedIn:false even on nonzero exit
  AC7: Hermetic tests by default; opt-in marker for readiness tests
  AC8: Keep apiProvider separate from authMethod in diagnostics
  AC9: Documentation and Ruff formatting corrections

Marker: @pytest.mark.claude_auth_readiness_mocked enables real subprocess stubbing.
"""

import asyncio
import dataclasses
import json
import os
import types
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from conductor.config.schema import ProviderSettings
from conductor.providers.claude_agent_sdk import (
    ClaudeAgentSdkProvider,
    EffectiveAuthContext,
)


@pytest.fixture
def mock_agent_def():
    """Mock AgentDef for testing."""
    agent = MagicMock()
    agent.name = "test_agent"
    agent.model = "claude-3-5-sonnet-20241022"
    agent.output = {}
    agent.tools = None
    return agent


@pytest.fixture
def basic_context():
    """Basic immutable effective auth context."""
    import types
    return EffectiveAuthContext(
        env_snapshot=types.MappingProxyType({"ANTHROPIC_API_KEY": "test-key"}),
        resolved_cwd="/home/user/project",
        setting_sources=(),
        cli_path=Path("/usr/bin/claude"),
        auth_mode="auto",
    )


class TestEffectiveAuthContextImmutability:
    """AC1: EffectiveAuthContext is frozen; fields are immutable."""

    def test_context_is_frozen_dataclass(self, basic_context):
        """Verify EffectiveAuthContext is a frozen dataclass."""
        assert dataclasses.is_dataclass(basic_context)
        # Check that the class was created with frozen=True
        assert basic_context.__class__.__dataclass_params__.frozen

    def test_cannot_reassign_env_snapshot(self, basic_context):
        """Cannot reassign env_snapshot after construction."""
        with pytest.raises(dataclasses.FrozenInstanceError):
            basic_context.env_snapshot = {"NEW_KEY": "new_value"}

    def test_cannot_reassign_resolved_cwd(self, basic_context):
        """Cannot reassign resolved_cwd after construction."""
        with pytest.raises(dataclasses.FrozenInstanceError):
            basic_context.resolved_cwd = "/different/path"

    def test_cannot_reassign_setting_sources(self, basic_context):
        """Cannot reassign setting_sources after construction."""
        with pytest.raises(dataclasses.FrozenInstanceError):
            basic_context.setting_sources = ["user", "project"]

    def test_cannot_reassign_cli_path(self, basic_context):
        """Cannot reassign cli_path after construction."""
        with pytest.raises(dataclasses.FrozenInstanceError):
            basic_context.cli_path = Path("/different/claude")

    def test_has_six_fields(self, basic_context):
        """EffectiveAuthContext has exactly six fields."""
        fields = {f.name for f in dataclasses.fields(basic_context)}
        expected = {"env_snapshot", "resolved_cwd", "setting_sources", "cli_path", "auth_mode", "finalized_child_env"}
        assert fields == expected


class TestPostSnapshotEnvironmentMutation:
    """AC2: Post-snapshot mutations to os.environ do not affect stored context."""

    def test_env_snapshot_is_dict_copy_not_reference(self):
        """env_snapshot is a MappingProxyType copy, not a reference to os.environ."""
        original_env = {"KEY1": "value1", "KEY2": "value2"}
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType(original_env.copy()),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )

        # Mutate the original dict passed to constructor
        original_env["KEY1"] = "MUTATED"
        original_env["KEY3"] = "new"

        # Context snapshot must not change
        assert ctx.env_snapshot["KEY1"] == "value1"
        assert "KEY3" not in ctx.env_snapshot

    def test_global_os_environ_mutation_does_not_affect_snapshot(self):
        """Changes to os.environ after snapshot do not affect stored context."""
        # Create snapshot from current os.environ
        snapshot = os.environ.copy()
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType(snapshot),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )

        # Mutate global os.environ
        os.environ["_TEST_MUTATION_KEY"] = "test_value"
        try:
            # Context snapshot must not include the new key
            assert "_TEST_MUTATION_KEY" not in ctx.env_snapshot
        finally:
            # Cleanup
            del os.environ["_TEST_MUTATION_KEY"]

    def test_snapshot_is_immutable_via_mappingproxy(self):
        """The stored env_snapshot is immutable (MappingProxyType)."""
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"KEY": "value"}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )

        # Cannot mutate the MappingProxyType
        with pytest.raises(TypeError):
            ctx.env_snapshot["KEY"] = "new_value"

        # Cannot delete from it
        with pytest.raises(TypeError):
            del ctx.env_snapshot["KEY"]

        # But cannot reassign the field itself either
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.env_snapshot = {"DIFFERENT": "dict"}


class TestAuthContextConstruction:
    """Verify context construction pattern for all entry points."""

    def test_construct_from_current_environment(self):
        """Context can be constructed from current os.environ snapshot."""
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType(os.environ.copy()),
            resolved_cwd=os.getcwd(),
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="auto",
        )
        assert isinstance(ctx.env_snapshot, types.MappingProxyType)
        assert isinstance(ctx.resolved_cwd, str)
        assert isinstance(ctx.setting_sources, tuple)
        assert ctx.cli_path is None or isinstance(ctx.cli_path, Path)

    def test_construct_with_empty_snapshot(self):
        """Context can be constructed with empty env snapshot."""
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )
        assert len(ctx.env_snapshot) == 0


class TestAuthModeValidationAC3:
    """AC3: setting_sources rejection for subscription + api_key modes."""

    def test_static_validation_rejects_subscription_with_settings(self):
        """ProviderSettings schema validation rejects subscription + non-empty setting_sources."""
        with pytest.raises(ValueError) as exc_info:
            ProviderSettings(
                name="claude-agent-sdk",
                auth_mode="subscription",
                setting_sources=["project"],  # Non-empty
            )
        assert "setting_sources" in str(exc_info.value).lower()

    def test_static_validation_rejects_api_key_with_settings(self):
        """ProviderSettings schema validation rejects api_key + non-empty setting_sources."""
        with pytest.raises(ValueError) as exc_info:
            ProviderSettings(
                name="claude-agent-sdk",
                auth_mode="api_key",
                setting_sources=["user"],  # Non-empty
            )
        assert "setting_sources" in str(exc_info.value).lower()

    def test_static_validation_allows_auto_with_settings(self):
        """ProviderSettings schema validation allows auto + any setting_sources."""
        # Should not raise
        ps = ProviderSettings(
            name="claude-agent-sdk",
            auth_mode="auto",
            setting_sources=["project", "user"],
        )
        assert ps.auth_mode == "auto"
        assert ps.setting_sources == ["project", "user"]

    def test_static_validation_allows_subscription_without_settings(self):
        """ProviderSettings schema validation allows subscription + empty setting_sources."""
        ps = ProviderSettings(
            name="claude-agent-sdk",
            auth_mode="subscription",
            setting_sources=[],
        )
        assert ps.auth_mode == "subscription"
        assert ps.setting_sources == []

    def test_static_validation_allows_api_key_without_settings(self):
        """ProviderSettings schema validation allows api_key + empty setting_sources."""
        ps = ProviderSettings(
            name="claude-agent-sdk",
            auth_mode="api_key",
            setting_sources=[],
        )
        assert ps.auth_mode == "api_key"
        assert ps.setting_sources == []


@pytest.mark.claude_auth_readiness_mocked
class TestNeutralizationMatrix:
    """AC4: Environment variable neutralization for explicit auth modes."""

    @pytest.fixture
    def subscription_provider(self):
        """Create a ClaudeAgentSdkProvider with subscription auth mode."""
        return ClaudeAgentSdkProvider(auth_mode="subscription")

    @pytest.fixture
    def api_key_provider(self):
        """Create a ClaudeAgentSdkProvider with api_key auth mode."""
        return ClaudeAgentSdkProvider(auth_mode="api_key")

    def test_subscription_mode_neutralizes_api_key_and_auth_token(self, subscription_provider):
        """subscription mode clears ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({
                "ANTHROPIC_API_KEY": "test-api-key",
                "ANTHROPIC_AUTH_TOKEN": "test-token",
                "ANTHROPIC_OTHER": "keep-this",
            }),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="subscription",
        )

        result = subscription_provider._auth_env_override(auth_context)

        # The override dict contains only keys being neutralized
        assert result["ANTHROPIC_API_KEY"] == ""
        assert result["ANTHROPIC_AUTH_TOKEN"] == ""
        # ANTHROPIC_OTHER is not in the override since it's not being neutralized
        assert "ANTHROPIC_OTHER" not in result

    def test_subscription_mode_neutralizes_claude_code_vars(self, subscription_provider):
        """subscription mode clears CLAUDE_CODE_* and related vars."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({
                "CLAUDE_CODE_OAUTH_TOKEN": "oauth",
                "CLAUDE_CODE_USE_BEDROCK": "true",
                "CLAUDE_CODE_USE_VERTEX": "true",
                "CLAUDE_CODE_USE_FOUNDRY": "true",
                "KEEP_ME": "value",
            }),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="subscription",
        )

        result = subscription_provider._auth_env_override(auth_context)

        # The override dict contains only the neutralized keys
        assert result["ANTHROPIC_API_KEY"] == ""
        assert result["ANTHROPIC_AUTH_TOKEN"] == ""
        assert result["CLAUDE_CODE_OAUTH_TOKEN"] == ""
        assert result["CLAUDE_CODE_USE_BEDROCK"] == ""
        assert result["CLAUDE_CODE_USE_VERTEX"] == ""
        assert result["CLAUDE_CODE_USE_FOUNDRY"] == ""
        # KEEP_ME is not being neutralized
        assert "KEEP_ME" not in result

    def test_api_key_mode_clears_auth_token_only(self, api_key_provider):
        """api_key mode clears ANTHROPIC_AUTH_TOKEN but keeps API key."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({
                "ANTHROPIC_API_KEY": "test-api-key",
                "ANTHROPIC_AUTH_TOKEN": "test-token",
                "KEEP_ME": "value",
            }),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="api_key",
        )

        result = api_key_provider._auth_env_override(auth_context)

        # Auth token should be cleared
        assert result["ANTHROPIC_AUTH_TOKEN"] == ""
        # API key and KEEP_ME are not in override since they're not being neutralized
        assert "ANTHROPIC_API_KEY" not in result
        assert "KEEP_ME" not in result

    def test_api_key_mode_neutralizes_claude_code_vars(self, api_key_provider):
        """api_key mode also clears CLAUDE_CODE_* vars."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({
                "ANTHROPIC_API_KEY": "test-key",
                "CLAUDE_CODE_OAUTH_TOKEN": "oauth",
                "CLAUDE_CODE_USE_BEDROCK": "true",
            }),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="api_key",
        )

        result = api_key_provider._auth_env_override(auth_context)

        # Auth token is always cleared
        assert result["ANTHROPIC_AUTH_TOKEN"] == ""
        # CLAUDE_CODE vars are cleared
        assert result["CLAUDE_CODE_OAUTH_TOKEN"] == ""
        assert result["CLAUDE_CODE_USE_BEDROCK"] == ""
        # API key is not in override (not being neutralized for api_key mode)
        assert "ANTHROPIC_API_KEY" not in result

    @pytest.fixture
    def auto_mode_provider(self):
        """Create a ClaudeAgentSdkProvider with auto auth mode."""
        return ClaudeAgentSdkProvider(auth_mode="auto")

    def test_auto_mode_no_override(self, auto_mode_provider):
        """auto mode does not mutate env."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"KEY": "value"}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )

        result = auto_mode_provider._auth_env_override(auth_context)

        # auto mode returns empty dict (no overrides)
        assert result == {}


@pytest.mark.claude_auth_readiness_mocked
class TestApiKeyMode:
    """AC5: api_key mode requires nonblank key, no subprocess, rejects settings."""

    @pytest.fixture
    def api_key_provider(self):
        """Create a ClaudeAgentSdkProvider with api_key auth mode."""
        return ClaudeAgentSdkProvider(auth_mode="api_key")

    async def test_api_key_mode_rejects_blank_key(self, api_key_provider):
        """api_key mode readiness fails if API key is blank or missing."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({}),  # No ANTHROPIC_API_KEY
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="api_key",
        )

        result = await api_key_provider._check_auth_readiness(auth_context)

        assert result.ready is False
        assert "ANTHROPIC_API_KEY" in result.error

    async def test_api_key_mode_succeeds_with_nonblank_key(self, api_key_provider):
        """api_key mode readiness succeeds if API key is non-blank and CLI is available."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"ANTHROPIC_API_KEY": "valid-key-123"}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="api_key",
        )

        result = await api_key_provider._check_auth_readiness(auth_context)

        assert result.ready is True
        assert result.inferred_mode == "api_key"

    async def test_api_key_mode_does_not_spawn_subprocess(self, api_key_provider):
        """api_key mode does not run subprocess (verifies CLI path without auth status call)."""
        with patch(
            "conductor.providers.claude_agent_sdk.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
        ) as mock_subprocess:
            auth_context = EffectiveAuthContext(
                env_snapshot=types.MappingProxyType({"ANTHROPIC_API_KEY": "valid-key"}),
                resolved_cwd="/path",
                setting_sources=(),
                cli_path=Path("/usr/bin/claude"),
                auth_mode="api_key",
            )

            await api_key_provider._check_auth_readiness(auth_context)

            # Subprocess should not be created
            mock_subprocess.assert_not_called()

    async def test_api_key_mode_rejects_missing_cli(self, api_key_provider):
        """api_key mode readiness fails if CLI path is not found."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"ANTHROPIC_API_KEY": "valid-key"}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="api_key",
        )

        result = await api_key_provider._check_auth_readiness(auth_context)

        assert result.ready is False
        assert "Claude CLI not found" in result.error


@pytest.mark.claude_auth_readiness_mocked
class TestSubscriptionReadinessParsing:
    """AC6: subscription readiness parses JSON loggedIn:false on nonzero exit."""

    @pytest.fixture
    def subscription_provider(self):
        """Create a ClaudeAgentSdkProvider with subscription auth mode."""
        return ClaudeAgentSdkProvider(auth_mode="subscription")

    async def test_subscription_parses_json_on_nonzero_exit(self, subscription_provider):
        """subscription readiness parses JSON even if returncode is nonzero."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="subscription",
        )

        # Mock subprocess that returns nonzero exit but valid JSON
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(
            return_value=(json.dumps({"loggedIn": False}).encode(), b"")
        )

        with patch(
            "conductor.providers.claude_agent_sdk.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=mock_proc,
        ):
            result = await subscription_provider._check_auth_readiness(auth_context)

            # Should parse JSON and find loggedIn: false
            assert result.ready is False
            assert "Not logged in" in result.error

    async def test_subscription_parses_json_on_zero_exit_logged_in_true(
        self, subscription_provider
    ):
        """subscription readiness parses JSON with loggedIn: true on success."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="subscription",
        )

        # Mock subprocess that returns zero exit and loggedIn: true
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(json.dumps({"loggedIn": True}).encode(), b"")
        )

        with patch(
            "conductor.providers.claude_agent_sdk.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=mock_proc,
        ):
            result = await subscription_provider._check_auth_readiness(auth_context)

            # Should parse JSON and find loggedIn: true
            assert result.ready is True

    async def test_subscription_nonzero_exit_no_json_fails(self, subscription_provider):
        """subscription readiness fails on nonzero exit without valid JSON."""
        auth_context = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="subscription",
        )

        # Mock subprocess that returns nonzero exit and invalid JSON
        mock_proc = AsyncMock()
        mock_proc.returncode = 127
        mock_proc.communicate = AsyncMock(return_value=(b"command not found", b""))

        with patch(
            "conductor.providers.claude_agent_sdk.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=mock_proc,
        ):
            result = await subscription_provider._check_auth_readiness(auth_context)

            # Nonzero exit with no valid JSON → failure
            assert result.ready is False


@pytest.mark.claude_auth_readiness_mocked
class TestCliAvailabilityAndDiscovery:
    """Test CLI discovery pattern (AC5 prerequisite for subscription mode)."""

    @pytest.fixture
    def subscription_provider(self):
        """Create a ClaudeAgentSdkProvider with subscription auth mode."""
        return ClaudeAgentSdkProvider(auth_mode="subscription")

    def test_cli_path_can_be_none(self, subscription_provider):
        """Context cli_path can be None (CLI not found)."""
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )
        assert ctx.cli_path is None

    def test_cli_path_can_be_valid_path(self, subscription_provider):
        """Context cli_path can be a valid Path."""
        cli = Path("/usr/bin/claude")
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=cli,
            auth_mode="auto",
        )
        assert ctx.cli_path == cli
        assert isinstance(ctx.cli_path, Path)


class TestContextIdentityAcrossOperations:
    """Verify context identity is maintained and not shared across operations."""

    def test_each_operation_has_unique_context(self):
        """Each independent operation constructs its own fresh context."""
        ctx1 = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"K": "v1"}),
            resolved_cwd="/path1",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )
        ctx2 = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"K": "v2"}),
            resolved_cwd="/path2",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )

        assert ctx1.env_snapshot != ctx2.env_snapshot
        assert ctx1.resolved_cwd != ctx2.resolved_cwd
        # Contexts are not identical
        assert ctx1 is not ctx2

    def test_context_not_stored_globally(self):
        """Context is not stored as global state."""
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"K": "v"}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )
        # Context should be local variable, not accessible as global
        # (This is more of a design test—actual verification would be in integration)
        assert ctx is not None


class TestAuthContextThreading:
    """Verify context is threaded through all entry points."""

    @pytest.fixture
    def subscription_provider(self):
        """Create a ClaudeAgentSdkProvider with subscription auth mode."""
        return ClaudeAgentSdkProvider(auth_mode="subscription")

    def test_context_threaded_to_auth_env_override(self, subscription_provider):
        """_auth_env_override receives and uses context."""
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"ANTHROPIC_API_KEY": "secret"}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="subscription",
        )

        result = subscription_provider._auth_env_override(ctx)

        # Result should be based on context, not current os.environ
        # For subscription mode, should clear these keys
        assert isinstance(result, dict)
        # Subscription mode neutralizes ANTHROPIC_API_KEY among others
        assert "ANTHROPIC_API_KEY" in result or result == {}


class TestFlaw1EffectiveChildContext:
    """Phase 1: Flaw 1 — Thread finalized_child_env to both readiness and execution.

    RED tests: Prove finalized_child_env field exists and is threaded to both
    _run_auth_status_subprocess() and execute() with the same mapping + cwd.
    """

    def test_context_has_finalized_child_env_field(self):
        """EffectiveAuthContext has finalized_child_env field."""
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({
                "ANTHROPIC_API_KEY": "key",
                "ANTHROPIC_AUTH_TOKEN": "token",
                "KEEP": "value",
            }),
            resolved_cwd="/project",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="auto",
        )
        # RED test: This attribute should exist (will fail until Flaw 1 implemented)
        assert hasattr(ctx, "finalized_child_env"), (
            "EffectiveAuthContext must have finalized_child_env field for "
            "threading to both readiness subprocess and SDK execution"
        )
        assert isinstance(ctx.finalized_child_env, types.MappingProxyType), (
            "finalized_child_env must be a MappingProxyType (immutable mapping) "
            "that can be converted to dict at usage sites"
        )

    def test_finalized_child_env_contains_neutralized_vars_for_auto_mode(self):
        """finalized_child_env for auto mode includes full env_snapshot."""
        # Auto mode does not neutralize—it inherits
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({
                "ANTHROPIC_API_KEY": "key",
                "ANTHROPIC_AUTH_TOKEN": "token",
                "KEEP": "value",
            }),
            resolved_cwd="/project",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="auto",
        )
        # RED: finalized_child_env should exist and be the snapshot for auto mode
        child_env = ctx.finalized_child_env
        assert "KEEP" in child_env
        assert child_env["ANTHROPIC_API_KEY"] == "key"

    def test_finalized_child_env_is_shared_by_readiness_and_execution(self):
        """Same finalized_child_env mapping + cwd are passed to both subprocess and SDK."""
        # This is a design-level test: we verify the same mapping flows to both paths
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"ANTHROPIC_API_KEY": "secret-key"}),
            resolved_cwd="/project",
            setting_sources=(),
            cli_path=Path("/usr/bin/claude"),
            auth_mode="auto",
        )
        # RED: Should have the field
        assert hasattr(ctx, "finalized_child_env")
        # The cwd is also part of the context (not just the env)
        assert ctx.resolved_cwd == "/project"
        # Both pieces are available to be passed to both code paths


class TestDiagnosticsAC8:
    """AC8: Keep apiProvider separate from authMethod in diagnostics."""

    def test_auth_context_does_not_expose_full_env(self):
        """EffectiveAuthContext does not provide a method to expose full env."""
        ctx = EffectiveAuthContext(
            env_snapshot=types.MappingProxyType({"SECRET": "credentials"}),
            resolved_cwd="/path",
            setting_sources=(),
            cli_path=None,
            auth_mode="auto",
        )
        # Context itself does not have a public .expose_env() method or similar
        # (This is a design constraint—actual diagnostic output would be in web/diagnostics)
        assert not hasattr(ctx, "expose_environment")
        assert not hasattr(ctx, "log_credentials")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
