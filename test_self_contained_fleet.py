"""Self-contained fleet integration tests.

Tests fleet protocol messages, security, bottles, and registry concepts
without requiring external agent modules (git-agent, keeper-agent, etc.).

These tests cover the core fleet infrastructure that all agents depend on.
"""

import sys
import os
import json
import time
import unittest
from pathlib import Path

# Add fleet-protocol to path (it exists in sibling directory)
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


# ═══════════════════════════════════════════════════════════════════════════
# MESSAGE SERIALIZATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestMessageCreation(unittest.TestCase):
    """Test fleet message creation and field access."""

    def test_create_request_message(self):
        msg = (MessageBuilder()
               .sender("agent-a")
               .recipient("agent-b")
               .type(MessageType.REQUEST)
               .payload({"action": "ping"})
               .build())
        self.assertEqual(msg.header.sender, "agent-a")
        self.assertEqual(msg.header.recipient, "agent-b")

    def test_create_event_message(self):
        msg = (MessageBuilder()
               .sender("src")
               .recipient("dst")
               .type(MessageType.EVENT)
               .payload({"type": "heartbeat"})
               .build())
        self.assertEqual(msg.header.message_type, MessageType.EVENT.value)

    def test_create_command_message(self):
        msg = (MessageBuilder()
               .sender("cmd")
               .recipient("tgt")
               .type(MessageType.COMMAND)
               .payload({"cmd": "deploy"})
               .build())
        self.assertEqual(msg.header.message_type, MessageType.COMMAND.value)

    def test_create_query_message(self):
        msg = (MessageBuilder()
               .sender("src")
               .recipient("tgt")
               .type(MessageType.QUERY)
               .payload({"q": "status"})
               .build())
        self.assertEqual(msg.header.message_type, MessageType.QUERY.value)

    def test_create_status_message(self):
        msg = (MessageBuilder()
               .sender("src")
               .recipient("tgt")
               .type(MessageType.STATUS)
               .payload({"cpu": 50})
               .build())
        self.assertEqual(msg.header.message_type, MessageType.STATUS.value)

    def test_create_response_message(self):
        msg = (MessageBuilder()
               .sender("src")
               .recipient("tgt")
               .type(MessageType.RESPONSE)
               .payload({"result": "ok"})
               .build())
        self.assertEqual(msg.header.message_type, MessageType.RESPONSE.value)

    def test_create_error_message(self):
        msg = (MessageBuilder()
               .sender("src")
               .recipient("tgt")
               .type(MessageType.ERROR)
               .payload({"error": "not found"})
               .build())
        self.assertEqual(msg.header.message_type, MessageType.ERROR.value)

    def test_message_has_unique_id(self):
        msg1 = (MessageBuilder().sender("a").recipient("b").type(MessageType.EVENT).build())
        msg2 = (MessageBuilder().sender("a").recipient("b").type(MessageType.EVENT).build())
        self.assertNotEqual(msg1.header.message_id, msg2.header.message_id)


class TestMessageSerialization(unittest.TestCase):
    """Test message serialization round-trips."""

    def test_json_round_trip(self):
        msg = (MessageBuilder()
               .sender("a")
               .recipient("b")
               .type(MessageType.REQUEST)
               .payload({"key": "value", "num": 42})
               .priority(MessagePriority.HIGH)
               .ttl(600)
               .requires_ack(True)
               .build())
        json_str = msg.to_json()
        restored = FleetMessage.from_json(json_str)
        self.assertEqual(restored.header.sender, "a")
        self.assertEqual(restored.body.payload["key"], "value")
        self.assertEqual(restored.metadata.priority, MessagePriority.HIGH.value)
        self.assertEqual(restored.metadata.ttl, 600)
        self.assertTrue(restored.metadata.requires_ack)

    def test_binary_round_trip(self):
        msg = (MessageBuilder()
               .sender("a")
               .recipient("b")
               .type(MessageType.EVENT)
               .payload({"type": "HB"})
               .build())
        binary = msg.to_binary()
        restored = FleetMessage.from_binary(binary)
        self.assertEqual(restored.header.message_type, MessageType.EVENT.value)

    def test_dict_round_trip(self):
        msg = (MessageBuilder()
               .sender("x")
               .recipient("y")
               .type(MessageType.COMMAND)
               .payload({"cmd": "go"})
               .build())
        d = msg.to_dict()
        restored = FleetMessage.from_dict(d)
        self.assertEqual(restored.header.sender, "x")

    def test_message_copy_independent(self):
        msg = (MessageBuilder()
               .sender("a")
               .recipient("b")
               .type(MessageType.QUERY)
               .payload({"q": "test"})
               .build())
        copy = msg.copy()
        copy.body.payload["q"] = "modified"
        self.assertEqual(msg.body.payload["q"], "test")


class TestMessageValidation(unittest.TestCase):
    """Test message validation."""

    def test_valid_message_passes(self):
        msg = (MessageBuilder()
               .sender("a")
               .recipient("b")
               .type(MessageType.REQUEST)
               .build())
        valid, errors = MessageValidator.validate(msg)
        self.assertTrue(valid)

    def test_empty_sender_fails(self):
        msg = FleetMessage.from_dict({
            "header": {"sender": "", "recipient": "b", "message_type": "REQUEST",
                        "timestamp": 1.0, "message_id": "abc"},
        })
        valid, errors = MessageValidator.validate(msg)
        self.assertFalse(valid)

    def test_all_seven_types_valid(self):
        for mt in MessageType:
            msg = (MessageBuilder()
                   .sender("s")
                   .recipient("r")
                   .type(mt)
                   .build())
            valid, errors = MessageValidator.validate(msg)
            self.assertTrue(valid, f"Type {mt} failed validation")


# ═══════════════════════════════════════════════════════════════════════════
# REGISTRY TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestRegistryBasics(unittest.TestCase):
    """Test fleet registry operations."""

    def test_register_single_agent(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", name="Agent 1"))
        self.assertEqual(reg.agent_count(), 1)

    def test_register_multiple_agents(self):
        reg = FleetRegistry()
        for i in range(10):
            reg.register_agent(AgentRecord(agent_id=f"agent-{i}"))
        self.assertEqual(reg.agent_count(), 10)

    def test_get_agent(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="target"))
        agent = reg.get_agent("target")
        self.assertIsNotNone(agent)
        self.assertEqual(agent.agent_id, "target")

    def test_get_missing_agent(self):
        reg = FleetRegistry()
        agent = reg.get_agent("nonexistent")
        self.assertIsNone(agent)

    def test_service_providers(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", capabilities=["gpu", "storage"]))
        reg.register_agent(AgentRecord(agent_id="a2", capabilities=["gpu"]))
        providers = reg.get_service_providers("gpu")
        self.assertIn("a1", providers)
        self.assertIn("a2", providers)
        storage = reg.get_service_providers("storage")
        self.assertIn("a1", storage)
        self.assertNotIn("a2", storage)

    def test_service_not_found(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", capabilities=["gpu"]))
        providers = reg.get_service_providers("nonexistent_service")
        self.assertEqual(len(providers), 0)


class TestRegistrySnapshot(unittest.TestCase):
    """Test registry snapshot operations."""

    def test_snapshot_roundtrip(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="snap-test", capabilities=["x"]))
        snap = reg.get_snapshot()
        reg2 = FleetRegistry()
        success, conflicts = reg2.apply_snapshot(snap)
        self.assertTrue(success)
        agent = reg2.get_agent("snap-test")
        self.assertEqual(agent.capabilities, ["x"])


# ═══════════════════════════════════════════════════════════════════════════
# BOTTLE ROUTING TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestBottleCreation(unittest.TestCase):
    """Test bottle creation and fields."""

    def test_basic_bottle(self):
        bottle = Bottle(sender="a", intended_recipient="b", payload={"msg": "hi"})
        self.assertEqual(bottle.sender, "a")
        self.assertEqual(bottle.intended_recipient, "b")

    def test_bottle_with_conditions(self):
        bottle = Bottle(
            sender="a",
            intended_recipient="b",
            conditions=[DeliveryCondition(
                condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                target="b",
            )],
        )
        self.assertEqual(len(bottle.conditions), 1)

    def test_bottle_default_status(self):
        bottle = Bottle(sender="a", intended_recipient="b")
        self.assertIsNotNone(bottle.status)


class TestBottleRouter(unittest.TestCase):
    """Test bottle routing between agents."""

    def test_immediate_delivery(self):
        router = BottleRouter()
        bottle = Bottle(sender="a", intended_recipient="b", payload={"msg": "hi"})
        router.send(bottle)
        inbox = router.get_inbox("b")
        self.assertEqual(bottle.status, BottleStatus.DELIVERED.value)
        self.assertEqual(inbox.count(), 1)

    def test_priority_ordering(self):
        router = BottleRouter()
        low = Bottle(sender="a", intended_recipient="b", priority=0, payload={"p": "low"})
        high = Bottle(sender="a", intended_recipient="b", priority=3, payload={"p": "high"})
        router.send(low)
        router.send(high)
        inbox = router.get_inbox("b")
        retrieved = inbox.retrieve_by_priority()
        self.assertEqual(retrieved[0].payload["p"], "high")
        self.assertEqual(retrieved[1].payload["p"], "low")

    def test_event_triggered_delivery(self):
        router = BottleRouter()
        bottle = Bottle(
            sender="a",
            intended_recipient="b",
            conditions=[DeliveryCondition(
                condition_type=DeliveryConditionType.ON_EVENT.value,
                target="deploy_done",
            )],
        )
        router.send(bottle)
        self.assertEqual(router.get_pending_count(), 1)
        router.fire_event("deploy_done")
        delivered = router.process_pending()
        self.assertEqual(len(delivered), 1)

    def test_agent_online_condition(self):
        router = BottleRouter()
        router.set_online_agents({"a"})
        bottle = Bottle(
            sender="a",
            intended_recipient="b",
            conditions=[DeliveryCondition(
                condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                target="b",
            )],
        )
        router.send(bottle)
        self.assertEqual(bottle.status, BottleStatus.CONDITION_NOT_MET.value)
        router.set_online_agents({"a", "b"})
        delivered = router.process_pending()
        self.assertEqual(len(delivered), 1)


# ═══════════════════════════════════════════════════════════════════════════
# SECURITY TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestAgentIdentity(unittest.TestCase):
    """Test agent identity generation."""

    def test_generate_identity(self):
        id_a = AgentIdentity.generate("agent-a")
        self.assertEqual(id_a.agent_id, "agent-a")
        self.assertTrue(len(id_a.public_key) > 20)
        self.assertEqual(len(id_a.private_key), 32)

    def test_unique_identities(self):
        id_a = AgentIdentity.generate("a")
        id_b = AgentIdentity.generate("b")
        self.assertNotEqual(id_a.public_key, id_b.public_key)
        self.assertNotEqual(id_a.private_key, id_b.private_key)

    def test_identity_export_import(self):
        original = AgentIdentity.generate("export-test")
        exported = original.export()
        imported = AgentIdentity.import_identity(exported)
        self.assertEqual(imported.agent_id, "export-test")
        self.assertEqual(imported.public_key, original.public_key)


class TestMessageAuthentication(unittest.TestCase):
    """Test message signing and verification."""

    def test_sign_and_verify_data(self):
        identity = AgentIdentity.generate("signer")
        data = b"important message"
        sig = MessageAuthenticator.sign_data(data, identity.private_key)
        self.assertTrue(MessageAuthenticator.verify_data(data, sig, identity.private_key))

    def test_tampered_data_fails(self):
        identity = AgentIdentity.generate("signer")
        data = b"original message"
        sig = MessageAuthenticator.sign_data(data, identity.private_key)
        tampered = b"tampered message"
        self.assertFalse(MessageAuthenticator.verify_data(tampered, sig, identity.private_key))

    def test_sign_message(self):
        identity = AgentIdentity.generate("signer")
        msg = (MessageBuilder()
               .sender("signer")
               .recipient("other")
               .type(MessageType.EVENT)
               .payload({"data": "hello"})
               .build())
        sig = MessageAuthenticator.sign(msg, identity)
        self.assertIsInstance(sig, str)
        self.assertTrue(len(sig) > 0)


class TestHMACAuthentication(unittest.TestCase):
    """Test HMAC-based authentication."""

    def test_hmac_round_trip(self):
        auth = HMACAuthenticator()
        msg = (MessageBuilder()
               .sender("a")
               .recipient("b")
               .type(MessageType.STATUS)
               .payload({"ts": 12345})
               .build())
        mac = auth.authenticate(msg)
        self.assertTrue(auth.verify(msg, mac))

    def test_different_messages_different_mac(self):
        auth = HMACAuthenticator()
        msg1 = (MessageBuilder().sender("a").recipient("b").type(MessageType.EVENT).payload({"x": 1}).build())
        msg2 = (MessageBuilder().sender("a").recipient("b").type(MessageType.EVENT).payload({"x": 2}).build())
        mac1 = auth.authenticate(msg1)
        mac2 = auth.authenticate(msg2)
        self.assertNotEqual(mac1, mac2)


class TestSecretRedaction(unittest.TestCase):
    """Test secret redaction."""

    def test_redact_api_key(self):
        redactor = SecretRedactor()
        text = "api_key=sk-live-abcdefghijklmnop"
        result = redactor.redact_string(text)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn("sk-live-abcdefghijklmnop", result)

    def test_clean_text_unchanged(self):
        redactor = SecretRedactor()
        text = "This is a clean message with no secrets"
        result = redactor.redact_string(text)
        self.assertNotIn("[REDACTED]", result)


class TestCryptoHelpers(unittest.TestCase):
    """Test cryptographic helper functions."""

    def test_generate_key(self):
        key = generate_key()
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_keys_unique(self):
        k1 = generate_key()
        k2 = generate_key()
        self.assertNotEqual(k1, k2)

    def test_b64encode_decode(self):
        data = b"hello world"
        encoded = b64encode(data)
        decoded = b64decode(encoded)
        self.assertEqual(decoded, data)

    def test_hash_data(self):
        h1 = hash_data(b"test")
        h2 = hash_data(b"test")
        self.assertEqual(h1, h2)
        h3 = hash_data(b"different")
        self.assertNotEqual(h1, h3)


# ═══════════════════════════════════════════════════════════════════════════
# HEARTBEAT PROTOCOL TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestHeartbeatProtocol(unittest.TestCase):
    """Test heartbeat protocol."""

    def test_alive_agent(self):
        hb = HeartbeatProtocol()
        hb.register("agent-1")
        hb.record_heartbeat("agent-1")
        self.assertEqual(hb.get_state("agent-1"), HeartbeatState.ALIVE)

    def test_dead_unknown_agent(self):
        hb = HeartbeatProtocol()
        self.assertEqual(hb.get_state("unknown"), HeartbeatState.DEAD)

    def test_degraded_state(self):
        from fleet_protocol.protocol import HeartbeatRecord
        record = HeartbeatRecord(agent_id="agent-1")
        record.update()
        self.assertEqual(record.state, HeartbeatState.ALIVE)
        record.last_heartbeat = time.time() - 12
        record.check_health()
        self.assertEqual(record.state, HeartbeatState.DEGRADED)

    def test_suspect_state(self):
        from fleet_protocol.protocol import HeartbeatRecord
        record = HeartbeatRecord(agent_id="agent-1")
        record.update()
        record.last_heartbeat = time.time() - 20
        record.check_health()
        self.assertEqual(record.state, HeartbeatState.SUSPECT)

    def test_dead_state(self):
        from fleet_protocol.protocol import HeartbeatRecord
        record = HeartbeatRecord(agent_id="agent-1")
        record.update()
        record.last_heartbeat = time.time() - 40
        record.check_health()
        self.assertEqual(record.state, HeartbeatState.DEAD)

    def test_get_alive_agents(self):
        hb = HeartbeatProtocol()
        hb.register("alive-1")
        hb.register("alive-2")
        hb.record_heartbeat("alive-1")
        alive = hb.get_alive_agents()
        self.assertIn("alive-1", alive)
        self.assertNotIn("alive-2", alive)


# ═══════════════════════════════════════════════════════════════════════════
# PROTOCOL ERROR HANDLING TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestErrorHandling(unittest.TestCase):
    """Test error codes and recovery procedures."""

    def test_error_codes_defined(self):
        # ErrorCode is an enum accessible by value
        codes = [e.name for e in ErrorCode]
        self.assertIn("HEARTBEAT_DEAD", codes)
        self.assertIn("INTERNAL_ERROR", codes)
        self.assertGreater(len(codes), 10)

    def test_error_message_function(self):
        msg = error_message("test error")
        self.assertIsInstance(msg, str)
        self.assertTrue(len(msg) > 0)

    def test_recovery_procedures_exist(self):
        self.assertIsInstance(RECOVERY_PROCEDURES, dict)

    def test_get_recovery_action(self):
        action = get_recovery_action("CONNECTION_FAILED")
        self.assertIsInstance(action, object)
        self.assertTrue(hasattr(action, 'action'))


class TestProtocolVersion(unittest.TestCase):
    """Test protocol version."""

    def test_version_defined(self):
        self.assertIsInstance(ProtocolVersion, type)

    def test_version_defined(self):
        members = list(ProtocolVersion)
        self.assertGreater(len(members), 0)
        v1 = ProtocolVersion.V1
        self.assertIsNotNone(v1)


if __name__ == "__main__":
    unittest.main()
