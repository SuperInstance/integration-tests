"""
test_trust_capability_integration.py — Trust × Capabilities (~150 lines)

Cross-agent integration tests verifying that trust scores affect capability
decisions, OCap tokens can be delegated across agents, trust attestations
can be imported/exported, and capability middleware correctly denies
unauthorized actions.
"""

import sys
import os
import json
import tempfile
import shutil
import unittest
from pathlib import Path

FLEET_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FLEET_ROOT / "trust-agent"))

from trust_engine import TrustEngine, TrustProfile, BASE_TRUST, trust_level_name
from capability_tokens import (
    CapabilityToken, CapabilityRegistry, CapabilityAction, BetaReputation,
    EXERCISE_TRUST_THRESHOLD, DELEGATION_TRUST_THRESHOLD,
)
from capability_middleware import (
    CapabilityMiddleware, CommandActionMap, CheckResult, reset_registry,
    TrustBridge, CapabilityAudit,
)
from trust_portability import (
    TrustAttestation, FleetTrustBridge, FLEET_TRUST_KEY,
    DEFAULT_IMPORT_FACTOR, BASE_TRUST,
)


class TestTrustAffectsCapabilities(unittest.TestCase):
    """Trust scores affect capability decisions."""

    def test_low_trust_denied_exercise(self):
        """Agent below trust threshold cannot exercise capabilities."""
        reg = CapabilityRegistry()
        reg._get_trust = lambda name: 0.1  # Very low trust

        token = reg.issue(
            action=CapabilityAction.BUILD_ROOM,
            holder="low-agent",
            issuer="system",
        )
        # Agent has token but trust is too low
        result = reg.exercise("low-agent", CapabilityAction.BUILD_ROOM)
        self.assertFalse(result["success"])

    def test_high_trust_allowed_exercise(self):
        """Agent above trust threshold can exercise capabilities."""
        reg = CapabilityRegistry()
        reg._get_trust = lambda name: 0.9  # High trust

        token = reg.issue(
            action=CapabilityAction.BUILD_ROOM,
            holder="high-agent",
            issuer="system",
        )
        result = reg.exercise("high-agent", CapabilityAction.BUILD_ROOM)
        self.assertTrue(result["success"])

    def test_trust_bridge_connects_engine_to_registry(self):
        """TrustBridge wires TrustEngine scores to CapabilityRegistry."""
        tmp = Path(tempfile.mkdtemp())
        try:
            engine = TrustEngine(data_dir=str(tmp / "trust"))
            reg = CapabilityRegistry(data_dir=str(tmp / "caps"))
            bridge = TrustBridge(
                registry=reg,
                trust_engine=engine,
            )

            # Record trust events to build up trust
            for _ in range(10):
                engine.record_event("test-agent", "task_completion", 0.9)

            trust = bridge.registry._get_trust("test-agent")
            self.assertGreater(trust, 0.3)  # Should be above threshold
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestOCapDelegation(unittest.TestCase):
    """OCap tokens can be delegated across agents."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_delegate_token(self):
        """Valid tokens can be delegated to another agent."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps"))
        reg._get_trust = lambda name: 0.8

        token = reg.issue(
            action=CapabilityAction.CREATE_ITEM,
            holder="agent-a",
            issuer="system",
        )
        delegated = reg.delegate(token.token_id, "agent-b", "agent-a")
        self.assertIsNotNone(delegated)
        self.assertEqual(delegated.holder, "agent-b")
        self.assertEqual(delegated.issuer, "agent-a")
        self.assertGreater(delegated.delegate_depth, 0)

    def test_delegation_requires_sufficient_trust(self):
        """Delegation requires sufficient trust from delegator."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps"))
        # Very low trust for the delegator
        reg._get_trust = lambda name: 0.1 if name == "poor-agent" else 0.8

        token = reg.issue(
            action=CapabilityAction.CREATE_ITEM,
            holder="poor-agent",
            issuer="system",
        )
        delegated = reg.delegate(token.token_id, "target-agent", "poor-agent")
        self.assertIsNone(delegated)

    def test_delegation_attenuates_permissions(self):
        """Delegated token is attenuated (restricted)."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps"))
        reg._get_trust = lambda name: 0.8

        token = reg.issue(
            action=CapabilityAction.CREATE_ITEM,
            holder="agent-a",
            issuer="system",
            max_uses=100,
        )
        delegated = reg.delegate(
            token.token_id, "agent-b", "agent-a", max_uses=10,
        )
        self.assertIsNotNone(delegated)
        self.assertLessEqual(delegated.max_uses, 10)

    def test_revoked_token_blocks_delegation(self):
        """Revoked tokens cannot be delegated."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps"))
        reg._get_trust = lambda name: 0.8

        token = reg.issue(
            action=CapabilityAction.BUILD_ROOM,
            holder="agent-a",
            issuer="system",
        )
        token.revoke("test revocation")
        delegated = reg.delegate(token.token_id, "agent-b", "agent-a")
        self.assertIsNone(delegated)


class TestTrustAttestationImportExport(unittest.TestCase):
    """Trust attestations can be imported/exported across agents."""

    def test_sign_and_verify_attestation(self):
        """Signed attestations pass verification."""
        att = TrustAttestation(
            agent_name="test-agent",
            issuer_repo="repo-alpha",
            issuer_id="issuer-1",
            composite=0.75,
            dimensions={"code_quality": 0.8, "task_completion": 0.7},
            event_count=50,
            is_meaningful=True,
        )
        att.sign(FLEET_TRUST_KEY)
        self.assertTrue(att.verify(FLEET_TRUST_KEY))

    def test_tampered_attestation_fails(self):
        """Tampered attestations fail verification."""
        att = TrustAttestation(
            agent_name="test-agent",
            issuer_repo="repo-alpha",
            composite=0.75,
        )
        att.sign(FLEET_TRUST_KEY)
        att.composite = 0.1
        # Recompute fingerprint won't match the original
        self.assertFalse(att.verify(FLEET_TRUST_KEY))

    def test_export_round_trip(self):
        """Export and import preserves attestation data."""
        att = TrustAttestation(
            agent_name="export-agent",
            issuer_repo="export-repo",
            composite=0.6,
            dimensions={"code_quality": 0.7, "task_completion": 0.5,
                         "collaboration": 0.8, "reliability": 0.4, "innovation": 0.6},
            event_count=30,
            is_meaningful=True,
            cross_repo_events=["repo-b", "repo-c"],
        )
        att.sign(FLEET_TRUST_KEY)
        json_str = att.to_json()
        restored = TrustAttestation.from_json(json_str)
        self.assertTrue(restored.verify(FLEET_TRUST_KEY))
        self.assertEqual(restored.agent_name, "export-agent")
        self.assertEqual(restored.composite, 0.6)
        self.assertTrue(restored.is_meaningful)

    def test_fleet_bridge_accepts_valid_attestation(self):
        """FleetTrustBridge accepts valid attestations."""
        bridge = FleetTrustBridge(
            local_repo="local-repo",
            import_factor=0.5,
        )
        att = TrustAttestation(
            agent_name="remote-agent",
            issuer_repo="remote-repo",
            composite=0.7,
            event_count=20,
            is_meaningful=True,
        )
        att.sign(FLEET_TRUST_KEY)
        result = bridge.import_attestation(att)
        self.assertTrue(result["accepted"])

    def test_fleet_bridge_rejects_tampered(self):
        """FleetTrustBridge rejects tampered attestations."""
        bridge = FleetTrustBridge(
            local_repo="local-repo",
            import_factor=0.5,
        )
        att = TrustAttestation(
            agent_name="bad-agent",
            issuer_repo="remote-repo",
            composite=0.7,
        )
        att.sign(FLEET_TRUST_KEY)
        att.dimensions["code_quality"] = 0.99
        result = bridge.import_attestation(att)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "invalid_signature")

    def test_replay_detection(self):
        """FleetTrustBridge detects replayed attestations."""
        bridge = FleetTrustBridge(
            local_repo="local-repo",
            import_factor=0.5,
        )
        att = TrustAttestation(
            agent_name="replay-agent",
            issuer_repo="remote-repo",
            composite=0.7,
        )
        att.sign(FLEET_TRUST_KEY)

        result1 = bridge.import_attestation(att)
        self.assertTrue(result1["accepted"])

        result2 = bridge.import_attestation(att)
        self.assertFalse(result2["accepted"])
        self.assertEqual(result2["reason"], "replay_detected")


class TestCapabilityMiddlewareDeniesUnauthorized(unittest.TestCase):
    """Capability middleware correctly denies unauthorized actions."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        reset_registry()

    def test_ungated_command_passes(self):
        """Ungated commands are allowed through middleware."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps"))
        mw = CapabilityMiddleware(registry=reg)
        result = mw.check_command("look", "agent-x")
        self.assertTrue(result.allowed)
        self.assertEqual(result.via, "none")

    def test_gated_command_without_token_denied(self):
        """Gated command fails for agent with no token."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps"))
        reg._get_trust = lambda name: 0.5
        mw = CapabilityMiddleware(registry=reg)
        result = mw.check_command("build", "no-token-agent")
        self.assertFalse(result.allowed)

    def test_gated_command_with_token_allowed(self):
        """Gated command succeeds for agent with valid token."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps"))
        reg._get_trust = lambda name: 0.8
        reg.issue(
            action=CapabilityAction.BUILD_ROOM,
            holder="token-agent",
            issuer="system",
        )
        mw = CapabilityMiddleware(registry=reg)
        result = mw.check_command("build", "token-agent")
        self.assertTrue(result.allowed)
        self.assertEqual(result.via, "ocap")

    def test_acl_fallback_allows_high_level(self):
        """ACL fallback allows high-level agents without tokens."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps"))
        mw = CapabilityMiddleware(
            registry=reg,
            permission_levels={"acl-agent": 4},
        )
        result = mw.check_command("build", "acl-agent")
        self.assertTrue(result.allowed)
        self.assertEqual(result.via, "acl")

    def test_audit_trail_records_checks(self):
        """Middleware records all permission checks."""
        reg = CapabilityRegistry(data_dir=str(self.tmp / "caps))
        mw = CapabilityMiddleware(registry=reg)
        mw.check_command("look", "agent-x")
        mw.check_command("build", "agent-x")
        trail = mw.audit_trail
        self.assertEqual(len(trail), 2)


if __name__ == "__main__":
    unittest.main()
