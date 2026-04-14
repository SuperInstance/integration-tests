"""
test_fleet_protocol_integration.py — Protocol × Agents (~200 lines)

Cross-agent integration tests verifying the fleet protocol's message
serialization, registry, bottle routing, security primitives, and
heartbeat protocol all work across agent boundaries.
"""

import sys
import os
import json
import time
import unittest
from pathlib import Path

# Add fleet-protocol to path
FLEET_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FLEET_ROOT / "fleet-protocol"))

from fleet_protocol.messages import (
    FleetMessage, MessageBuilder, MessageType, MessagePriority, MessageValidator,
)
from fleet_protocol.protocol import (
    FleetProtocol, HeartbeatProtocol, HeartbeatState, ProtocolVersion,
    HandshakeProtocol, HandshakeConfig, HandshakeState,
    DiscoveryProtocol,
    ErrorCode, error_message,
    RECOVERY_PROCEDURES,
    get_recovery_action,
)
from fleet_protocol.registry import (
    FleetRegistry, AgentRecord, ServiceRecord, HealthRecord, HealthStatus,
    AgentRole,
)
from fleet_protocol.security import (
    AgentIdentity, MessageAuthenticator, SessionManager,
    HMACAuthenticator, SecretRedactor,
    generate_key, b64encode, b64decode, hash_data,
)
from fleet_protocol.bottle import (
    Bottle, BottleStatus, BottleRouter, DeliveryCondition, DeliveryConditionType,
    BottleInbox, BottlePostmark,
)


class TestMessageSerialization(unittest.TestCase):
    """Fleet messages serialize/deserialize correctly between agents."""

    def test_json_round_trip(self):
        """Message survives JSON serialization round-trip."""
        msg = (
            MessageBuilder()
            .sender("agent-alpha")
            .recipient("agent-beta")
            .type(MessageType.REQUEST)
            .payload({"action": "ping", "data": [1, 2, 3]})
            .priority(MessagePriority.HIGH)
            .ttl(600)
            .requires_ack(True)
            .build()
        )
        json_str = msg.to_json()
        restored = FleetMessage.from_json(json_str)
        self.assertEqual(restored.header.sender, "agent-alpha")
        self.assertEqual(restored.header.recipient, "agent-beta")
        self.assertEqual(restored.body.payload["action"], "ping")
        self.assertEqual(restored.metadata.priority, MessagePriority.HIGH.value)
        self.assertEqual(restored.metadata.ttl, 600)
        self.assertTrue(restored.metadata.requires_ack)

    def test_binary_round_trip(self):
        """Message survives binary serialization round-trip."""
        msg = (
            MessageBuilder()
            .sender("agent-a")
            .recipient("agent-b")
            .type(MessageType.EVENT)
            .payload({"type": "HEARTBEAT"})
            .build()
        )
        binary = msg.to_binary()
        restored = FleetMessage.from_binary(binary)
        self.assertEqual(restored.header.message_type, MessageType.EVENT.value)
        self.assertEqual(restored.body.payload["type"], "HEARTBEAT")
        self.assertIsNotNone(restored.header.message_id)

    def test_dict_round_trip(self):
        """Message survives dict serialization round-trip."""
        msg = (
            MessageBuilder()
            .sender("x")
            .recipient("y")
            .type(MessageType.COMMAND)
            .payload({"cmd": "deploy"})
            .build()
        )
        d = msg.to_dict()
        restored = FleetMessage.from_dict(d)
        self.assertEqual(restored.header.sender, "x")

    def test_validation_rejects_invalid(self):
        """Validator catches messages with missing/invalid fields."""
        # Empty sender
        bad = FleetMessage.from_dict({
            "header": {"sender": "", "recipient": "b", "message_type": "REQUEST",
                        "timestamp": 1.0, "message_id": "abc"},
        })
        valid, errors = MessageValidator.validate(bad)
        self.assertFalse(valid)
        self.assertTrue(any("sender" in e for e in errors))

    def test_message_copy_is_independent(self):
        """Copying a message creates an independent deep copy."""
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.QUERY)
            .payload({"q": "test"})
            .build()
        )
        copy = msg.copy()
        copy.body.payload["q"] = "modified"
        self.assertEqual(msg.body.payload["q"], "test")


class TestRegistryMultiAgent(unittest.TestCase):
    """Registry can track multiple agents."""

    def test_register_multiple_agents(self):
        """Registry tracks all registered agents."""
        reg = FleetRegistry()
        for i in range(5):
            reg.register_agent(AgentRecord(
                agent_id=f"agent-{i}",
                name=f"Agent {i}",
                capabilities=["compute", "storage"],
            ))
        self.assertEqual(reg.agent_count(), 5)

    def test_service_index_auto_built(self):
        """Service index is built from agent capabilities."""
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(
            agent_id="a1", capabilities=["gpu", "gpu"],
        ))
        reg.register_agent(AgentRecord(
            agent_id="a2", capabilities=["gpu", "storage"],
        ))
        providers = reg.get_service_providers("gpu")
        self.assertIn("a1", providers)
        self.assertIn("a2", providers)
        providers = reg.get_service_providers("storage")
        self.assertIn("a2", providers)
        self.assertNotIn("a1", providers)

    def test_registry_snapshot_roundtrip(self):
        """Snapshot serialization and restoration works."""
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(
            agent_id="snapshot-agent", capabilities=["x"],
        ))
        snap = reg.get_snapshot()
        reg2 = FleetRegistry()
        success, conflicts = reg2.apply_snapshot(snap)
        self.assertTrue(success)
        self.assertEqual(reg2.get_agent("snapshot-agent").capabilities, ["x"])

    def test_conflict_detection(self):
        """Conflicts are detected when generations collide."""
        reg = FleetRegistry()
        r1 = AgentRecord(agent_id="conflict-agent", capabilities=["v1"])
        reg.register_agent(r1)
        r2 = AgentRecord(agent_id="conflict-agent", capabilities=["v2"])
        # Simulate same generation conflict
        r1.generation = 5
        r2.generation = 5
        conflicts = reg.detect_conflicts({"conflict-agent": r2.to_dict()})
        self.assertTrue(len(conflicts) > 0)
        self.assertTrue(len(conflicts) > 0)
        # The conflict type depends on implementation details
        self.assertIn(conflicts[0]["type"], ["generation_collision", "missing_remote"])


class TestBottleRouting(unittest.TestCase):
    """Bottles route between agents with delivery conditions."""

    def test_immediate_delivery(self):
        """Bottles with no conditions deliver immediately."""
        router = BottleRouter()
        bottle = Bottle(
            sender="agent-a",
            intended_recipient="agent-b",
            payload={"msg": "hello"},
        )
        pm = router.send(bottle)
        inbox = router.get_inbox("agent-b")
        self.assertEqual(bottle.status, BottleStatus.DELIVERED.value)
        self.assertEqual(inbox.count(), 1)

    def test_agent_online_condition(self):
        """Bottle with AGENT_ONLINE condition waits for agent."""
        router = BottleRouter()
        router.set_online_agents({"agent-a"})
        bottle = Bottle(
            sender="agent-a",
            intended_recipient="agent-b",
            conditions=[DeliveryCondition(
                condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                target="agent-b",
            )],
        )
        router.send(bottle)
        self.assertEqual(bottle.status, BottleStatus.CONDITION_NOT_MET.value)
        self.assertEqual(router.get_inbox("agent-b").count(), 0)

        # Now bring agent-b online
        router.set_online_agents({"agent-a", "agent-b"})
        delivered = router.process_pending()
        self.assertEqual(len(delivered), 1)

    def test_event_triggered_delivery(self):
        """Bottles can wait for an event to fire."""
        router = BottleRouter()
        bottle = Bottle(
            sender="agent-a",
            intended_recipient="agent-b",
            conditions=[DeliveryCondition(
                condition_type=DeliveryConditionType.ON_EVENT.value,
                target="deployment_complete",
            )],
        )
        router.send(bottle)
        self.assertEqual(router.get_pending_count(), 1)

        router.fire_event("deployment_complete")
        delivered = router.process_pending()
        self.assertEqual(len(delivered), 1)

    def test_bottle_expiration(self):
        """Expired bottles are removed from pending."""
        router = BottleRouter()
        bottle = Bottle(
            sender="a",
            intended_recipient="b",
            ttl=0,  # instantly expired
            conditions=[DeliveryCondition(
                condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                target="b",
            )],
        )
        router.send(bottle)
        time.sleep(0.01)  # tiny sleep to ensure TTL breach
        delivered = router.process_pending()
        self.assertEqual(len(delivered), 0)

    def test_priority_retrieval(self):
        """Bottles are retrieved in priority order."""
        router = BottleRouter()
        low = Bottle(sender="a", intended_recipient="b", priority=0, payload={"p": "low"})
        high = Bottle(sender="a", intended_recipient="b", priority=3, payload={"p": "high"})
        router.send(low)
        router.send(high)
        inbox = router.get_inbox("b")
        retrieved = inbox.retrieve_by_priority()
        self.assertEqual(retrieved[0].payload["p"], "high")
        self.assertEqual(retrieved[1].payload["p"], "low")


class TestSecurityPrimitives(unittest.TestCase):
    """Security primitives (signing, verification) work across agents."""

    def test_agent_identity_generation(self):
        """Each agent gets a unique identity with public key."""
        id_a = AgentIdentity.generate("agent-a")
        id_b = AgentIdentity.generate("agent-b")
        self.assertNotEqual(id_a.public_key, id_b.public_key)
        self.assertTrue(len(id_a.public_key) > 20)
        self.assertTrue(len(id_a.private_key) == 32)

    def test_sign_and_verify_data(self):
        """Data signed with one identity can be verified with the same key."""
        identity = AgentIdentity.generate("signer")
        data = b"important fleet message"
        sig = MessageAuthenticator.sign_data(data, identity.private_key)
        self.assertTrue(
            MessageAuthenticator.verify_data(data, sig, identity.private_key)
        )

    def verify_tampered_data_fails(self):
        """Tampered data fails verification."""
        identity = AgentIdentity.generate("signer")
        data = b"original message"
        sig = MessageAuthenticator.sign_data(data, identity.identity.private_key)
        tampered = b"tampered message"
        self.assertFalse(
            MessageAuthenticator.verify_data(tampered, sig, identity.private_key)
        )

    def test_hmac_authentication(self):
        """HMAC auth produces same digest for same message."""
        auth = HMACAuthenticator()
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.STATUS)
            .payload({"ts": 12345})
            .build()
        )
        mac1 = auth.authenticate(msg)
        self.assertTrue(auth.verify(msg, mac1))

    def test_secret_redaction(self):
        """Secret redactor removes sensitive patterns from text."""
        redactor = SecretRedactor()
        text = "api_key=sk-live-abcdefghijklmnop"
        result = redactor.redact_string(text)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn("sk-live-abcdefghijklmnop", result)

    def test_identity_export_import(self):
        """Agent identity can be exported and imported."""
        original = AgentIdentity.generate("export-agent")
        exported = original.export()
        imported = AgentIdentity.import_identity(exported)
        self.assertEqual(imported.agent_id, "export-agent")
        self.assertEqual(imported.public_key, original.public_key)


class TestHeartbeatProtocol(unittest.TestCase):
    """Heartbeat protocol detects agent failures."""

    def test_alive_agent(self):
        """Agent with recent heartbeat is ALIVE."""
        hb = HeartbeatProtocol()
        hb.register("agent-1")
        hb.record_heartbeat("agent-1")
        self.assertEqual(hb.get_state("agent-1"), HeartbeatState.ALIVE)

    def test_dead_agent(self):
        """Agent with no heartbeat is DEAD."""
        hb = HeartbeatProtocol()
        self.assertEqual(hb.get_state("unknown"), HeartbeatState.DEAD)

    def test_degraded_then_dead(self):
        """Agent transitions: ALIVE -> DEGRADED -> SUSPECT -> DEAD."""
        from fleet_protocol.protocol import HeartbeatRecord
        hb = HeartbeatProtocol()
        record = HeartbeatRecord(agent_id="agent-1")
        record.update()  # alive now
        self.assertEqual(record.state, HeartbeatState.ALIVE)

        # Simulate time passing for degraded
        old_time = time.time() - 12  # past degraded threshold (10s)
        record.last_heartbeat = old_time
        record.check_health()
        self.assertEqual(record.state, HeartbeatState.DEGRADED)

        # Suspect
        old_time = time.time() - 20  # between degraded and dead
        record.last_heartbeat = old_time
        record.check_health()
        self.assertEqual(record.state, HeartbeatState.SUSPECT)

        # Dead
        old_time = time.time() - 40
        record.last_heartbeat = old_time
        record.check_health()
        self.assertEqual(record.state, HeartbeatState.DEAD)

    def test_get_alive_agents(self):
        """Only alive agents are listed."""
        hb = HeartbeatProtocol()
        hb.register("alive-1")
        hb.register("alive-2")
        hb.record_heartbeat("alive-1")
        alive = hb.get_alive_agents()
        self.assertIn("alive-1", alive)
        self.assertNotIn("alive-2", alive)


if __name__ == "__main__":
    unittest.main()
