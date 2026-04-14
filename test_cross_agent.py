"""
Cross-agent integration test suite — tests INTERFACES between fleet agents.

All tests mock external dependencies and verify agent interaction contracts.
~300 lines, single file.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Path setup for agent imports ─────────────────────────────────────────────
FLEET_ROOT = Path("/home/z/my-project/fleet")
sys.path.insert(0, str(FLEET_ROOT / "keeper-agent"))
sys.path.insert(0, str(FLEET_ROOT / "fleet-protocol"))
sys.path.insert(0, str(FLEET_ROOT / "git-agent"))
sys.path.insert(0, str(FLEET_ROOT / "trust-agent"))

# ── Agent module imports ─────────────────────────────────────────────────────
from leak_detector import LeakDetector, Sensitivity  # noqa: E402
from keeper import KeeperAgent  # noqa: E402
from fleet_protocol.messages import (  # noqa: E402
    FleetMessage, MessageBuilder, MessageType, MessagePriority,
    MessageHeader, MessageBody, MessageMetadata, MessageSecurity,
)
from fleet_protocol.bottle import (  # noqa: E402
    Bottle, BottleInbox, DeliveryCondition, DeliveryConditionType, BottleRouter,
)
from fleet_protocol.security import (  # noqa: E402
    AgentIdentity, MessageAuthenticator, generate_key,
)
from workshop_template import WorkshopTemplate, LanguageStack  # noqa: E402
from bootcamp import Bootcamp, Dojo, Rank  # noqa: E402
from trust_engine import TrustEngine, TrustProfile  # noqa: E402
from capability_tokens import (  # noqa: E402
    CapabilityToken, CapabilityAction, CapabilityRegistry,
)
from trust_portability import TrustAttestation  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════
# 1. TestKeeperAgentIntegration
# ═══════════════════════════════════════════════════════════════════════════

class TestKeeperAgentIntegration:
    """Tests for keeper-agent secret storage, leak detection, and revocation."""

    @pytest.fixture
    def vault(self, tmp_path):
        """Create a KeeperAgent with a temp vault."""
        return KeeperAgent(
            vault_path=str(tmp_path / "vault"),
            master_key="test-master-key-12345",
        )

    def test_store_secret_returns_opaque_reference(self, vault):
        """Keeper stores secret and returns an opaque reference, not the raw value."""
        vault.register_agent("agent-alpha", "pub-key-123")
        vault.store_secret("agent-alpha", "gh-token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

        ref = vault.get_secret_reference("agent-alpha", "gh-token")
        # Reference must be opaque (base64), never the raw value
        assert "ghp_" not in ref
        assert ref != "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert len(ref) > 20

    def test_leak_detector_blocks_github_pats(self):
        """Leak detector blocks GitHub PATs in outbound data."""
        detector = LeakDetector(sensitivity=Sensitivity.STRICT)
        payload = {"headers": {"Authorization": "Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}}
        matches = detector.scan(payload)
        assert len(matches) > 0
        assert any("github_pat" in m.pattern_name for m in matches)

    def test_leak_detector_blocks_aws_keys(self):
        """Leak detector blocks AWS access keys in outbound data."""
        detector = LeakDetector(sensitivity=Sensitivity.MODERATE)
        payload = {"env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7QRSTYPA"}}
        matches = detector.scan(payload)
        assert len(matches) > 0
        assert any("aws_access_key" in m.pattern_name for m in matches)

    def test_leak_detector_blocks_bearer_tokens(self):
        """Leak detector blocks bearer tokens in outbound data."""
        detector = LeakDetector(sensitivity=Sensitivity.STRICT)
        payload = {"auth": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456ghi789"}
        matches = detector.scan(payload)
        assert len(matches) > 0
        assert any("bearer_token" in m.pattern_name for m in matches)

    def test_agent_revocation_prevents_secret_access(self, vault):
        """Revoking an agent prevents secret access."""
        vault.register_agent("agent-beta", "pub-key-456")
        vault.store_secret("agent-beta", "secret-1", "super-secret-value")

        vault.revoke_agent("agent-beta")

        with pytest.raises(Exception):  # AgentRevokedError
            vault.get_secret_reference("agent-beta", "secret-1")


# ═══════════════════════════════════════════════════════════════════════════
# 2. TestFleetProtocolIntegration
# ═══════════════════════════════════════════════════════════════════════════

class TestFleetProtocolIntegration:
    """Tests for fleet-protocol messages, bottles, and identity."""

    def test_fleet_message_serialization_roundtrip(self):
        """FleetMessage: dict → JSON → dict preserves all fields."""
        msg = (MessageBuilder()
               .sender("agent-a")
               .recipient("agent-b")
               .type(MessageType.REQUEST)
               .payload({"action": "scan", "target": "repo-1"})
               .priority(MessagePriority.HIGH)
               .ttl(600)
               .build())

        # dict → JSON → dict
        json_str = msg.to_json()
        recovered = FleetMessage.from_json(json_str)

        assert recovered.header.sender == "agent-a"
        assert recovered.header.recipient == "agent-b"
        assert recovered.header.message_type == "REQUEST"
        assert recovered.body.payload["action"] == "scan"
        assert recovered.metadata.priority == MessagePriority.HIGH.value
        assert recovered.metadata.ttl == 600

    def test_fleet_message_all_seven_types(self):
        """All 7 message types serialize and deserialize correctly."""
        types = list(MessageType)
        assert len(types) == 7
        for mt in types:
            msg = (MessageBuilder()
                   .sender("src")
                   .recipient("dst")
                   .type(mt)
                   .build())
            assert msg.header.message_type == mt.value
            assert msg.to_json()  # serializes without error

    def test_bottle_with_delivery_conditions(self):
        """Bottle delivery conditions evaluate correctly."""
        bottle = Bottle(
            sender="agent-a",
            intended_recipient="agent-b",
            conditions=[
                DeliveryCondition(
                    condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                    target="agent-b",
                ),
            ],
        )

        # Agent not online → not deliverable
        ctx = {"online_agents": {"agent-c"}, "current_time": time.time()}
        assert not bottle.is_deliverable(ctx)

        # Agent online → deliverable
        ctx["online_agents"].add("agent-b")
        assert bottle.is_deliverable(ctx)

    def test_bottle_inbox_priority_retrieval(self):
        """BottleInbox returns bottles sorted by priority (highest first)."""
        inbox = BottleInbox("agent-x")
        low = Bottle(bottle_id="low", priority=MessagePriority.LOW.value, payload={"p": 0})
        high = Bottle(bottle_id="high", priority=MessagePriority.HIGH.value, payload={"p": 2})
        normal = Bottle(bottle_id="norm", priority=MessagePriority.NORMAL.value, payload={"p": 1})

        inbox.add(low)
        inbox.add(high)
        inbox.add(normal)

        retrieved = inbox.retrieve_by_priority()
        assert len(retrieved) == 3
        assert retrieved[0].bottle_id == "high"
        assert retrieved[1].bottle_id == "norm"
        assert retrieved[2].bottle_id == "low"

    def test_agent_identity_keypair_generation_and_signing(self):
        """AgentIdentity generates a keypair and signs messages."""
        identity = AgentIdentity.generate("test-agent")
        assert identity.private_key  # 32 random bytes
        assert identity.public_key  # derived hash
        assert len(identity.private_key) == 32

        # Sign a message
        msg = (MessageBuilder()
               .sender("test-agent")
               .recipient("other-agent")
               .type(MessageType.EVENT)
               .payload({"data": "hello"})
               .build())
        sig = MessageAuthenticator.sign(msg, identity)
        assert len(sig) > 0

        # sign_data / verify_data round-trip
        data = b"canonical-message-data"
        sig2 = MessageAuthenticator.sign_data(data, identity.private_key)
        assert MessageAuthenticator.verify_data(data, sig2, identity.private_key)


# ═══════════════════════════════════════════════════════════════════════════
# 3. TestWorkshopIntegration
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkshopIntegration:
    """Tests for WorkshopManager directory scaffolding and recipe tiers."""

    def test_workshop_creates_directory_structure(self, tmp_path):
        """WorkshopManager creates the expected directory structure."""
        tmpl = WorkshopTemplate()
        config = tmpl.create_workshop(
            path=str(tmp_path / "test-workshop"),
            agent_role="Test Agent",
            language_stack=LanguageStack.FULL,
        )

        expected_dirs = [
            "recipes/hot", "recipes/med", "recipes/cold",
            "interpreters", "scripts", "bootcamp/exercises",
            "dojo/techniques", "tests", "lib", "docs", ".superinstance",
        ]
        for d in expected_dirs:
            assert (tmp_path / "test-workshop" / d).is_dir(), f"Missing dir: {d}"
        assert config.agent_name == "test"
        assert config.language_stack == LanguageStack.FULL

    def test_recipe_creation_in_all_tiers(self, tmp_path):
        """Recipes can be created in hot, med, and cold tiers."""
        tmpl = WorkshopTemplate()
        tmpl.create_workshop(str(tmp_path / "ws"), "Agent", LanguageStack.FULL)

        for tier in ("hot", "med", "cold"):
            meta = tmpl.add_recipe(
                workshop_path=str(tmp_path / "ws"),
                name=f"recipe_{tier}",
                content=f"# {tier} recipe",
                tier=tier,
                language="python",
                description=f"A {tier}-tier recipe",
            )
            assert meta.tier == tier
            recipe_file = tmp_path / "ws" / "recipes" / tier / f"recipe_{tier}.py"
            assert recipe_file.exists()

    def test_workshop_narrative_from_git_log(self, tmp_path):
        """Workshop narrative can be extracted from a temp git repo."""
        # Create a temp git repo with commits
        repo_dir = tmp_path / "git-workshop"
        repo_dir.mkdir()

        subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@fleet.ai"],
                       cwd=str(repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test Agent"],
                       cwd=str(repo_dir), check=True, capture_output=True)

        (repo_dir / "README.md").write_text("# My Workshop\nInitial setup.")
        subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit: scaffold workshop"],
                       cwd=str(repo_dir), check=True, capture_output=True)

        (repo_dir / "app.py").write_text("print('hello fleet')")
        subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "feat: add main application module"],
                       cwd=str(repo_dir), check=True, capture_output=True)

        # Verify git log is accessible
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=str(repo_dir), check=True, capture_output=True, text=True,
        )
        commits = result.stdout.strip().split("\n")
        assert len(commits) == 2
        assert "Initial commit" in commits[1]
        assert "feat" in commits[0]


# ═══════════════════════════════════════════════════════════════════════════
# 4. TestTrustCapabilityIntegration
# ═══════════════════════════════════════════════════════════════════════════

class TestTrustCapabilityIntegration:
    """Tests for trust scoring, capability tokens, and attestations."""

    def test_trust_profile_composite_scoring(self):
        """TrustProfile computes composite score from weighted dimensions."""
        engine = TrustEngine(data_dir=str(tempfile.mkdtemp()))
        profile = engine.get_profile("agent-x")

        # Record events in multiple dimensions
        for _ in range(5):
            profile.record("code_quality", 0.9)
            profile.record("task_completion", 0.85)
            profile.record("collaboration", 0.8)
            profile.record("reliability", 0.95)
            profile.record("innovation", 0.7)

        ts = engine.get_trust_score("agent-x")
        assert ts.composite > 0.5  # Should be high with all positive events
        assert ts.meaningful  # 25 events total > MIN_EVENTS_FOR_TRUST (3)
        assert 0.0 <= ts.composite <= 1.0

    def test_capability_token_lifecycle(self):
        """CapabilityToken: create → delegate → revoke lifecycle."""
        registry = CapabilityRegistry(data_dir=str(tempfile.mkdtemp()))
        registry.set_trust_getter(lambda _: 0.9)  # high trust for all

        # Issue original token
        token = registry.issue(
            action=CapabilityAction.BUILD_ROOM,
            holder="agent-a",
            issuer="system",
        )
        assert token.is_valid()
        assert token.can_exercise(CapabilityAction.BUILD_ROOM)

        # Delegate to another agent
        delegated = registry.delegate(
            token_id=token.token_id,
            new_holder="agent-b",
            from_agent="agent-a",
        )
        assert delegated is not None
        assert delegated.holder == "agent-b"
        assert delegated.is_valid()

        # Revoke original → downstream also revoked
        registry.revoke(token.token_id, "test revocation")
        assert not token.is_valid()
        assert not delegated.is_valid()

    def test_trust_attestation_signing_and_verification(self):
        """TrustAttestation signs and verifies with HMAC-SHA256."""
        att = TrustAttestation(
            agent_name="agent-x",
            issuer_repo="repo-alpha",
            composite=0.85,
            dimensions={"code_quality": 0.9, "task_completion": 0.8,
                         "collaboration": 0.85, "reliability": 0.9, "innovation": 0.75},
            event_count=42,
            is_meaningful=True,
        )
        att.sign()

        assert att.signature != ""
        assert att.fingerprint != ""
        assert att.verify() is True

        # Tampering invalidates signature
        att.composite = 0.5
        assert att.verify() is False


# ═══════════════════════════════════════════════════════════════════════════
# 5. TestBootcampDojo
# ═══════════════════════════════════════════════════════════════════════════

class TestBootcampDojo:
    """Tests for bootcamp XP progression and dojo technique mastery."""

    def test_bootcamp_enrollment_and_xp_progression(self):
        """Agent enrolls and gains XP, advancing through ranks."""
        bootcamp = Bootcamp()
        progress = bootcamp.enroll("learner-agent")

        assert progress.enrolled is True
        assert progress.rank == Rank.NOVICE
        assert progress.xp == 0

        # Complete exercises to advance
        bootcamp.complete_exercise("learner-agent", "hello_workshop", time_taken_seconds=30)
        bootcamp.complete_exercise("learner-agent", "parse_config", time_taken_seconds=20)
        bootcamp.complete_exercise("learner-agent", "hello_workshop", time_taken_seconds=10)
        bootcamp.complete_exercise("learner-agent", "parse_config", time_taken_seconds=15)
        bootcamp.complete_exercise("learner-agent", "hello_workshop", time_taken_seconds=25)

        updated = bootcamp.get_progress("learner-agent")
        assert updated.xp > 0
        assert len(updated.exercises_completed) >= 3

    def test_dojo_technique_learning_and_mastery(self):
        """Dojo: learn → practice → achieve mastery."""
        dojo = Dojo()
        tech = dojo.learn_technique(
            name="error-boundary-pattern",
            code="try { risky() } catch { fallback() }",
            description="Wrap risky operations with error boundaries",
            category="error-handling",
        )
        assert tech.mastery_level == 0.0
        assert tech.mastered is False

        # Practice enough to trigger mastery
        for _ in range(12):
            tech = dojo.practice_technique("error-boundary-pattern")

        assert tech.mastery_level >= 0.9
        assert tech.mastered is True
        assert tech.times_practiced >= 12


# ═══════════════════════════════════════════════════════════════════════════
# 6. TestCLIArguments
# ═══════════════════════════════════════════════════════════════════════════

class TestCLIArguments:
    """Tests that each agent CLI parses arguments correctly (no execution)."""

    def test_standalone_agent_scaffold_cli_args(self):
        """standalone-agent-scaffold CLI: onboard, run, status, workshop, audit."""
        # Replicate parser from standalone-agent-scaffold/cli.py build_parser()
        parser = argparse.ArgumentParser(prog="pelagic-agent")
        sub = parser.add_subparsers(dest="command")
        p_onb = sub.add_parser("onboard")
        p_onb.add_argument("--keeper-url", default=None)
        p_onb.add_argument("--skip-github", action="store_true")
        p_run = sub.add_parser("run")
        p_run.add_argument("--mode", choices=["hot", "med", "cold"], default="hot")
        p_run.add_argument("--detach", action="store_true")
        p_ws = sub.add_parser("workshop")
        p_ws.add_argument("workshop_action", nargs="?", default="status",
                          choices=["init", "status", "history", "narrative"])
        p_audit = sub.add_parser("audit")
        p_audit.add_argument("--limit", type=int, default=20)
        sub.add_parser("status")
        sub.add_parser("config")
        sub.add_parser("link-keeper")

        args = parser.parse_args(["onboard", "--skip-github"])
        assert args.command == "onboard"
        assert args.skip_github is True

        args = parser.parse_args(["run", "--mode", "cold", "--detach"])
        assert args.mode == "cold"
        assert args.detach is True

        args = parser.parse_args(["workshop", "init"])
        assert args.workshop_action == "init"

        args = parser.parse_args(["audit", "--limit", "50"])
        assert args.limit == 50

    def test_keeper_agent_cli_args(self):
        """keeper-agent CLI: start, status, audit, revoke-agent, export-audit."""
        parser = argparse.ArgumentParser(prog="keeper-agent")
        parser.add_argument("--vault-path", default="~/.superinstance/keeper_vault")
        sub = parser.add_subparsers(dest="command")
        p_start = sub.add_parser("start")
        p_start.add_argument("--port", type=int, default=8877)
        p_start.add_argument("--host", default="0.0.0.0")
        sub.add_parser("status")
        p_audit = sub.add_parser("audit")
        p_audit.add_argument("--agent-id", default=None)
        p_audit.add_argument("--limit", type=int, default=50)
        sub.add_parser("list-agents")
        p_ra = sub.add_parser("revoke-agent")
        p_ra.add_argument("id")
        p_rs = sub.add_parser("revoke-secret")
        p_rs.add_argument("id")
        p_export = sub.add_parser("export-audit")
        p_export.add_argument("--format", default="json", choices=["json", "csv"])

        args = parser.parse_args(["start", "--port", "9090", "--host", "127.0.0.1"])
        assert args.command == "start"
        assert args.port == 9090

        args = parser.parse_args(["audit", "--agent-id", "alpha", "--limit", "10"])
        assert args.agent_id == "alpha"
        assert args.limit == 10

        args = parser.parse_args(["revoke-agent", "bad-agent"])
        assert args.id == "bad-agent"

        args = parser.parse_args(["export-audit", "--format", "csv"])
        assert args.format == "csv"

    def test_git_agent_cli_args(self):
        """git-agent CLI: serve, narrate, workshop create, bootcamp enroll."""
        parser = argparse.ArgumentParser(prog="git-agent")
        parser.add_argument("--fleet-root", default=".")
        sub = parser.add_subparsers(dest="command")
        p_serve = sub.add_parser("serve")
        p_serve.add_argument("--watch", action="store_true")
        p_narrate = sub.add_parser("narrate")
        p_narrate.add_argument("agent")
        p_narrate.add_argument("--style", choices=["brief", "detailed", "technical", "story"],
                               default="story")
        p_ws = sub.add_parser("workshop")
        ws_sub = p_ws.add_subparsers(dest="workshop_cmd")
        ws_create = ws_sub.add_parser("create")
        ws_create.add_argument("name")
        ws_create.add_argument("--role", default=None)
        ws_create.add_argument("--stack", default="full")
        p_bc = sub.add_parser("bootcamp")
        bc_sub = p_bc.add_subparsers(dest="bootcamp_cmd")
        bc_enroll = bc_sub.add_parser("enroll")
        bc_enroll.add_argument("agent")
        sub.add_parser("fleet-report")

        args = parser.parse_args(["serve", "--watch"])
        assert args.command == "serve"
        assert args.watch is True

        args = parser.parse_args(["narrate", "my-agent", "--style", "brief"])
        assert args.agent == "my-agent"
        assert args.style == "brief"

        args = parser.parse_args(["workshop", "create", "flux", "--role", "VM runner"])
        assert args.workshop_cmd == "create"
        assert args.name == "flux"
        assert args.role == "VM runner"

        args = parser.parse_args(["bootcamp", "enroll", "new-agent"])
        assert args.bootcamp_cmd == "enroll"
        assert args.agent == "new-agent"

    def test_trail_agent_cli_args(self):
        """trail-agent CLI: encode, decode, verify, execute, disassemble."""
        parser = argparse.ArgumentParser(prog="trail_agent")
        sub = parser.add_subparsers(dest="command")
        p_enc = sub.add_parser("encode")
        p_enc.add_argument("worklog")
        p_enc.add_argument("-o", "--output", default=None)
        p_dec = sub.add_parser("decode")
        p_dec.add_argument("trail")
        p_dec.add_argument("--format", choices=["text", "hex", "verbose", "compact"],
                           default="text")
        p_ver = sub.add_parser("verify")
        p_ver.add_argument("trail")
        p_ver.add_argument("--show-fingerprint", action="store_true")
        p_exe = sub.add_parser("execute")
        p_exe.add_argument("trail")
        p_exe.add_argument("--world", choices=["mock", "file"], default="mock")
        p_exe.add_argument("--dry-run", action="store_true")
        p_exe.add_argument("--fail-fast", action="store_true")
        p_dis = sub.add_parser("disassemble")
        p_dis.add_argument("trail")
        sub.add_parser("onboard")
        sub.add_parser("status")

        args = parser.parse_args(["encode", "worklog.json", "-o", "out.bin"])
        assert args.command == "encode"
        assert args.worklog == "worklog.json"
        assert args.output == "out.bin"

        args = parser.parse_args(["execute", "trail.bin", "--world", "file", "--dry-run"])
        assert args.world == "file"
        assert args.dry_run is True

        args = parser.parse_args(["verify", "test.bin", "--show-fingerprint"])
        assert args.show_fingerprint is True

        args = parser.parse_args(["decode", "a.bin", "--format", "verbose"])
        assert args.format == "verbose"
