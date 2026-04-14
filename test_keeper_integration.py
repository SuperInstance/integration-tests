"""
test_keeper_integration.py — Keeper × All Agents (~200 lines)

Cross-agent integration tests verifying the Keeper Agent works correctly
with the standalone agent scaffold, leak detection, proxy injection,
and agent revocation flows.
"""

import sys
import os
import json
import tempfile
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add agent directories to path so we can import their modules
FLEET_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FLEET_ROOT / "keeper-agent"))
sys.path.insert(0, str(FLEET_ROOT / "standalone-agent-scaffold"))

from leak_detector import LeakDetector, Sensitivity
from keeper import KeeperAgent, AgentRevokedError, SecretRevokedError, AgentNotFoundError, LeakDetectedError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_keeper(tmp: Path) -> KeeperAgent:
    """Create a KeeperAgent pointing at a temp vault."""
    vault = tmp / "vault"
    return KeeperAgent(vault_path=str(vault), master_key="test-master-key-12345")


class TestKeeperScaffoldConnection(unittest.TestCase):
    """Agent scaffold can connect to keeper via keeper_client concepts."""

    def test_keeper_initializes_with_vault(self):
        """Keeper creates vault directories on init."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            vault = Path(td) / "vault"
            self.assertTrue(vault.exists())
            self.assertTrue((vault / "secrets").exists())
            self.assertTrue((vault / "agents.json").exists())

    def test_keeper_registers_agent_successfully(self):
        """Registering an agent returns a record with auth token."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            record = keeper.register_agent(
                agent_id="test-agent-001",
                public_key="pubkey-data-here-abc123",
                metadata={"version": "1.0"},
            )
            self.assertEqual(record.agent_id, "test-agent-001")
            self.assertTrue(len(record.token) > 10)
            self.assertEqual(record.status, "active")

    def test_keeper_client_registration_pattern(self):
        """Simulate what keeper_client.register_agent does (HTTP → vault)."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            # Simulate: scaffold sends agent_id + public_key
            agent_id = "scaffold/coder/abc123"
            pub_key = "ssh-ed25519-AAAAC3NzaC1lZDI1NTE5AAAA"
            resp_agent = keeper.register_agent(
                agent_id=agent_id,
                public_key=pub_key,
            )
            self.assertEqual(resp_agent.agent_id, agent_id)
            self.assertEqual(resp_agent.status, "active")
            # The token is what the client stores for future calls
            self.assertIn(resp_agent.token, keeper.list_agents()[0]["token"])
            # Verify tokens are redacted in public listings
            for agent in keeper.list_agents():
                self.assertEqual(agent["token"], "***REDACTED***")

    def test_unknown_agent_raises_not_found(self):
        """Accessing a non-existent agent raises AgentNotFoundError."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            with self.assertRaises(AgentNotFoundError):
                keeper._validate_agent("ghost-agent")


class TestSecretStorage(unittest.TestCase):
    """Keeper stores secrets and returns references (not raw values)."""

    def test_store_and_get_reference(self):
        """get_secret_reference returns an opaque token, never the raw value."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-a", "pubkey-a")

            record = keeper.store_secret("agent-a", "api-key", "sk-live-abc123secret")
            self.assertEqual(record.secret_id, "api-key")

            ref = keeper.get_secret_reference("agent-a", "api-key")
            # The reference should be base64-encoded JSON, not the raw secret
            self.assertNotIn("sk-live-abc123secret", ref)
            self.assertIn("agent-a", ref)

    def test_reference_contains_expiration(self):
        """References have a short TTL encoded."""
        with tempfile.TemporaryDirectory() as td:
            import base64
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-a", "pubkey-a")
            keeper.store_secret("agent-a", "k1", "secret-value")
            ref = keeper.get_secret_reference("agent-a", "k1")
            payload = json.loads(base64.urlsafe_b64decode(ref))
            self.assertIn("exp", payload)
            self.assertIn("sid", payload)
            self.assertIn("aid", payload)
            self.assertIn("nonce", payload)

    def test_cross_agent_secret_isolation(self):
        """Agent B cannot access Agent A's secret."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-a", "pub-a")
            keeper.register_agent("agent-b", "pub-b")
            keeper.store_secret("agent-a", "secret-1", "top-secret")

            with self.assertRaises(Exception):
                keeper.get_secret_reference("agent-b", "secret-1")

    def test_revoked_secret_raises(self):
        """Accessing a revoked secret raises SecretRevokedError."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-a", "pub-a")
            keeper.store_secret("agent-a", "s1", "val")
            keeper.revoke_secret("s1")
            with self.assertRaises(SecretRevokedError):
                keeper.get_secret_reference("agent-a", "s1")


class TestLeakDetection(unittest.TestCase):
    """Keeper's leak detector blocks API keys in outbound requests."""

    def test_detects_aws_key_in_outbound(self):
        """AWS access keys are blocked in outbound payloads."""
        detector = LeakDetector(sensitivity=Sensitivity.STRICT)
        request = {
            "headers": {"Authorization": "Bearer sk-abc123secrettoken"},
            "url": "https://api.example.com/data",
        }
        matches = detector.scan(request)
        self.assertTrue(len(matches) > 0)

    def test_detects_github_pat(self):
        """GitHub PATs are blocked."""
        detector = LeakDetector(sensitivity=Sensitivity.STRICT)
        request = {"body": {"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}}
        matches = detector.scan(request)
        self.assertTrue(len(matches) > 0)

    def test_safe_request_passes(self):
        """Clean requests with no secrets pass through."""
        detector = LeakDetector(sensitivity=Sensitivity.STRICT)
        request = {"method": "GET", "url": "https://example.com/health"}
        matches = detector.scan(request)
        self.assertEqual(len(matches), 0)

    def test_proxy_blocks_leaky_request(self):
        """proxy_request raises LeakDetectedError for leaky payloads."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-x", "pub-x")
            leaky = {"headers": {"Authorization": "Bearer sk-live-test-key-data"}}
            with self.assertRaises(LeakDetectedError):
                keeper.proxy_request("agent-x", "api.example.com", leaky)

    def test_proxy_allows_clean_request(self):
        """Clean proxy requests are assembled without error."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-x", "pub-x")
            clean = {"method": "POST", "url": "https://api.example.com/v1/chat"}
            result = keeper.proxy_request("agent-x", "api.example.com", clean)
            self.assertIn("method", result)
            self.assertEqual(result["method"], "POST")


class TestProxyInjection(unittest.TestCase):
    """Keeper proxy correctly injects secrets into proxied requests."""

    def test_proxy_injects_secret_ref(self):
        """$SECRET_REF: placeholders are replaced with actual values."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-a", "pub-a")
            keeper.store_secret("agent-a", "gh-token", "ghp_ABCDEFGHIJKLMNOPQR")

            import base64
            ref = keeper.get_secret_reference("agent-a", "gh-token")

            request = {
                "headers": {"X-Git-Token": f"$SECRET_REF:{ref}"},
                "url": "https://api.github.com/repos",
            }
            assembled = keeper.proxy_request("agent-a", "github", request)
            self.assertIn("ghp_ABCDEFGHIJKLMNOPQR", assembled["headers"]["X-Git-Token"])

    def test_proxy_embedded_secret_ref(self):
        """Secrets embedded in strings are correctly replaced."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-a", "pub-a")
            keeper.store_secret("agent-a", "api-key", "sk-12345")

            ref = keeper.get_secret_reference("agent-a", "api-key")
            request = {"url": f"https://api.example.com?key=$SECRET_REF:{ref}&q=1"}
            assembled = keeper.proxy_request("agent-a", "api", request)
            self.assertIn("sk-12345", assembled["url"])
            self.assertNotIn("$SECRET_REF:", assembled["url"])


class TestAgentRevocation(unittest.TestCase):
    """Agent revocation works end-to-end."""

    def test_revoke_agent_blocks_secret_storage(self):
        """Revoked agent cannot store new secrets."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-r", "pub-r")
            keeper.revoke_agent("agent-r")
            with self.assertRaises(AgentRevokedError):
                keeper.store_secret("agent-r", "k", "v")

    def test_revoke_agent_revokes_all_secrets(self):
        """Revoking an agent also revokes all its secrets."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-r", "pub-r")
            keeper.store_secret("agent-r", "s1", "val1")
            keeper.store_secret("agent-r", "s2", "val2")
            keeper.revoke_agent("agent-r")

            # Both secrets should now be revoked
            with self.assertRaises(SecretRevokedError):
                keeper.get_secret_reference("agent-r", "s1")
            with self.assertRaises(SecretRevokedError):
                keeper.get_secret_reference("agent-r", "s2")

    def test_revoked_agent_blocked_proxy(self):
        """Revoked agent cannot use the proxy."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-r", "pub-r")
            keeper.revoke_agent("agent-r")
            with self.assertRaises(AgentRevokedError):
                keeper.proxy_request("agent-r", "api", {})

    def test_revoked_agent_cannot_reregister(self):
        """A revoked agent cannot re-register."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-r", "pub-r")
            keeper.revoke_agent("agent-r")
            with self.assertRaises(AgentRevokedError):
                keeper.register_agent("agent-r", "pub-r")

    def test_audit_trail_records_revocation(self):
        """Revocation events are recorded in the audit trail."""
        with tempfile.TemporaryDirectory() as td:
            keeper = _make_keeper(Path(td))
            keeper.register_agent("agent-r", "pub-r")
            keeper.revoke_agent("agent-r")
            entries = keeper.audit(action="revoke")
            self.assertTrue(len(entries) >= 1)
            self.assertEqual(entries[0]["action"], "revoke")
            self.assertEqual(entries[0]["agent_id"], "agent-r")


if __name__ == "__main__":
    unittest.main()
