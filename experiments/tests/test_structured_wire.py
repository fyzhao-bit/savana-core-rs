"""agentd's private-planning wire as the stand-in mapper and planner serve it:
canonical CBOR against the literal vectors and mutations of agentd's own tests
(crates/savana-agentd/src/planner_privacy.rs, tests/planner_privacy_e2e.rs),
and the one-shot mutual-TLS endpoint's header and close rules. Never kernel,
model or benchmark evidence."""
import os
import socket
import ssl
import unittest

from savana_bench.structured_wire import (
    CatalogTool, EphemeralPki, MAPPER_PATH, MappedNode, OneShotServer, PLANNER_PATH, PlanStep, PlannerPlan,
    Relation, Slot, StructuralNode, StructuralRequest, WireError, Workflow, decode_mapper_request, decode_order,
    decode_ordered_plan, decode_plan, decode_structural_request, decode_workflow, encode_mapper_request,
    encode_ordered_plan, encode_plan, encode_structural_request, encode_workflow, mapper_request, request_header,
    response_bytes, validate_order, validate_workflow)


def node_id(byte):
    return bytes([byte]) * 16


def fixture_request(limits=(4, 3, 2, 4096)):
    """planner_privacy.rs `mapper_request()`: two slots, one relation, two tools."""
    return mapper_request(
        template=7, intent=2, actions=(10, 20),
        slots=(Slot(node_id(0xA1), 1, 1, 2), Slot(node_id(0xB2), 2, 2, 1)),
        relations=(Relation(1, node_id(0xA1), node_id(0xB2)),), limits=limits,
        active=((100, 10), (200, 20)),
        tools=(CatalogTool(200, 20, 3, 0x10, "sink_tool", "send transformed records"),
               CatalogTool(100, 10, 1, 0x01, "source_tool", "read source records")))


class StructuralVectorTests(unittest.TestCase):
    def test_request_is_the_closed_literal_wire_shape(self):
        request = StructuralRequest((StructuralNode(node_id(1), 1, 1, 0, 0),), ())
        expected = bytes([0x84, 0x02, 0x81, 0x85, 0x50]) + node_id(1) + bytes([0x01, 0x01, 0x00, 0x00, 0x80, 0x01])
        self.assertEqual(encode_structural_request(request), expected)
        self.assertEqual(decode_structural_request(expected), request)

    def test_unknown_tags_zero_ids_and_noncanonical_integers_are_refused(self):
        canonical = encode_structural_request(StructuralRequest((StructuralNode(node_id(1), 1, 1, 0, 0),), ()))
        role = bytearray(canonical)
        role[21] = 4
        zero = bytearray(canonical)
        zero[5:21] = bytes(16)
        effect = canonical[:22] + bytes([0x18, 0x80]) + canonical[23:]
        noncanonical = canonical[:21] + bytes([0x18, 0x01]) + canonical[22:]
        for malformed in (bytes(role), bytes(zero), effect, noncanonical, canonical + b"\x00", b""):
            with self.assertRaises(WireError):
                decode_structural_request(malformed)

    def test_graph_validation_mirrors_agentd(self):
        source, sink = StructuralNode(node_id(1), 1, 1, 0, 1), StructuralNode(node_id(2), 3, 0x10, 1, 0)
        forward = (node_id(1), node_id(2))
        valid = StructuralRequest((source, sink), (forward,))
        self.assertEqual(decode_structural_request(encode_structural_request(valid)), valid)
        for nodes, edges in (
                ((StructuralNode(node_id(1), 1, 1, 0, 0), StructuralNode(node_id(1), 3, 0x10, 0, 0)), ()),
                ((source, sink), ((node_id(1), node_id(3)),)),
                ((StructuralNode(node_id(1), 1, 1, 0, 2), StructuralNode(node_id(2), 3, 0x10, 2, 0)),
                 (forward, forward)),
                ((StructuralNode(node_id(1), 1, 1, 1, 1), StructuralNode(node_id(2), 3, 0x10, 1, 1)),
                 (forward, (node_id(2), node_id(1)))),
                ((StructuralNode(node_id(1), 1, 1, 0, 0), sink), (forward,)),
                ((StructuralNode(node_id(1), 2, 0x40, 0, 0),), ()),
                ((StructuralNode(node_id(1), 1, 0, 0, 0),), ())):
            with self.assertRaises(WireError):
                decode_structural_request(encode_structural_request(StructuralRequest(nodes, edges)))

    def test_ordered_reply_is_exact_and_noncanonical_lengths_are_refused(self):
        expected = bytes([0x82, 0x02, 0x82, 0x50]) + node_id(1) + b"\x50" + node_id(2)
        self.assertEqual(encode_ordered_plan([node_id(1), node_id(2)]), expected)
        self.assertEqual(decode_ordered_plan(expected), (node_id(1), node_id(2)))
        with self.assertRaises(WireError):
            decode_ordered_plan(expected[:2] + bytes([0x98, 0x02]) + expected[3:])

    def test_order_must_be_a_forward_permutation_of_the_request(self):
        request = StructuralRequest((StructuralNode(node_id(1), 1, 1, 0, 1), StructuralNode(node_id(2), 3, 0x10, 1, 0)),
                                    ((node_id(1), node_id(2)),))
        validate_order(request, (node_id(1), node_id(2)))
        for order in ((node_id(1),), (node_id(1), node_id(1)), (node_id(1), node_id(0xEE)), (node_id(2), node_id(1))):
            with self.assertRaises(WireError):
                validate_order(request, order)


class MapperVectorTests(unittest.TestCase):
    def test_mapper_request_round_trip_and_agentd_mutations(self):
        request = fixture_request()
        encoded = encode_mapper_request(request)
        self.assertEqual(decode_mapper_request(encoded), request)
        self.assertEqual([t.tool_class for t in request.tools], [100, 200])
        # The projection carries neither the route (99), nonce nor expiry.
        self.assertNotIn(bytes([0x18, 99]), encoded)
        row = encoded.index(bytes([0x86, 0x18, 0x64]))
        four = encoded[:row] + b"\x84" + encoded[row + 1:]
        text_template = encoded[:2] + b"\x60" + encoded[3:]
        intent = encoded[:3] + b"\x05" + encoded[4:]
        version = encoded[:1] + bytes([0x18, 0x02]) + encoded[2:]
        at = encoded.index(b"source_tool")
        unsafe = encoded[:at] + b"\n" + encoded[at + 1:]
        oversize = encoded[:at - 1] + bytes([0x79, 0x04, 0x01]) + b"a" * 1025 + encoded[at + len(b"source_tool"):]
        for malformed in (four, text_template, intent, version, unsafe, oversize, encoded + b"\x00"):
            with self.assertRaises(WireError):
                decode_mapper_request(malformed)

    def test_unsorted_or_duplicate_collections_are_refused(self):
        request = fixture_request()
        for changed in (request._replace(actions=(20, 10)), request._replace(tools=request.tools[::-1]),
                        request._replace(slots=request.slots[::-1]), request._replace(tools=request.tools[:1] * 2)):
            with self.assertRaises(WireError):
                decode_mapper_request(encode_mapper_request(changed))

    def test_inactive_tools_are_not_offered_to_the_mapper(self):
        request = mapper_request(template=7, intent=2, actions=(10, 20), slots=(), relations=(), limits=(4, 3, 2, 4096),
                                 active=((100, 10),), tools=fixture_request().tools)
        self.assertEqual([(t.tool_class, t.action) for t in request.tools], [(100, 10)])

    def test_workflow_bytes_and_agentd_checks(self):
        request = fixture_request()
        # tests/planner_privacy_e2e.rs `invalid_inactive_mapper_response`.
        inactive = Workflow((MappedNode(1, 999, 10, (), 1, 1),), ())
        self.assertEqual(encode_workflow(inactive).hex(), "83028186011903e70a80010180")
        with self.assertRaises(WireError):
            decode_workflow(encode_workflow(inactive), request)
        source = MappedNode(9, 100, 10, (("a", node_id(0xA1)),), 1, 1)
        sink = MappedNode(2, 200, 20, (("b", node_id(0xB2)),), 3, 0x10)
        workflow = Workflow((sink, source), ((9, 2),))
        encoded = encode_workflow(workflow)
        self.assertEqual(decode_workflow(encoded, request), workflow)
        with self.assertRaises(WireError):
            decode_workflow(encoded[:1] + bytes([0x18, 0x02]) + encoded[2:], request)
        unsorted = encode_workflow(Workflow((source, sink), ((9, 2),)))
        with self.assertRaises(WireError):
            decode_workflow(unsorted, request)
        for bad in (Workflow((source._replace(action=30),), ()), Workflow((source._replace(tool_class=999),), ()),
                    Workflow((source._replace(bindings=(("a", node_id(0xDD)),)),), ()),
                    Workflow((source._replace(role=2),), ()), Workflow((source._replace(effects=0x20),), ()),
                    Workflow((sink, source), ((2, 9), (9, 2))),
                    Workflow((sink, source._replace(bindings=(("b", node_id(0xA1)), ("a", node_id(0xA1))))), ())):
            with self.assertRaises(WireError):
                validate_workflow(request, bad)
        limited = fixture_request(limits=(2, 1, 1, 4096))
        with self.assertRaises(WireError):
            validate_workflow(limited, Workflow((source._replace(bindings=(("a", node_id(0xA1)),
                                                                           ("b", node_id(0xB2)))),), ()))

    def test_plan_bytes_and_step_rules(self):
        plan = PlannerPlan(b"\xcc" * 32, (PlanStep(1, 10, 100, (("z", node_id(0xA1)),), ()),
                                          PlanStep(2, 20, 200, (("a", node_id(0xB2)),), (1,))))
        encoded = encode_plan(plan)
        self.assertEqual(decode_plan(encoded), plan)
        # [2, nonce, [[ordinal, action, class, bindings, dependencies], ...]]
        self.assertEqual(encoded[:3], bytes([0x83, 0x02, 0x58]))
        for bad in (plan._replace(nonce=bytes(32)), plan._replace(steps=plan.steps[::-1]),
                    plan._replace(steps=(plan.steps[0], plan.steps[1]._replace(dependencies=(2,))))):
            with self.assertRaises(WireError):
                decode_plan(encode_plan(bad))

    def test_decode_order_mirrors_agentd_for_a_known_labeling(self):
        source = MappedNode(90, 100, 10, (("z", node_id(0xA1)),), 1, 1)
        sink = MappedNode(4, 200, 20, (("a", node_id(0xB2)),), 3, 0x10)
        labels = {node_id(0x31): 90, node_id(0x42): 4}
        steps = decode_order((sink, source), ((90, 4),), (node_id(0x31), node_id(0x42)), labels)
        self.assertEqual(steps, (PlanStep(1, 10, 100, (("z", node_id(0xA1)),), ()),
                                 PlanStep(2, 20, 200, (("a", node_id(0xB2)),), (1,))))
        with self.assertRaises(WireError):
            decode_order((sink, source), ((90, 4),), (node_id(0x42), node_id(0x31)), labels)


def _client_context(pki, *, identity=None, certificate=True):
    """Trusts `pki`'s CA; presents `identity`'s client certificate (default: the same run's)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=pki._ca_pem)
    pki = identity or pki
    context.set_alpn_protocols(["http/1.1"])
    if certificate:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        from cryptography import x509
        key = load_der_private_key(pki.client_key_der, None)
        chain = (x509.load_der_x509_certificate(pki.client_der).public_bytes(serialization.Encoding.PEM)
                 + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
        fd = os.memfd_create("test-client", os.MFD_CLOEXEC)
        try:
            os.write(fd, chain)
            context.load_cert_chain(f"/proc/self/fd/{fd}")
        finally:
            os.close(fd)
    return context


class EndpointTests(unittest.TestCase):
    HOST = "planner.structured.test"

    @classmethod
    def setUpClass(cls):
        cls.pki = EphemeralPki([cls.HOST])
        cls.other = EphemeralPki([cls.HOST])

    def setUp(self):
        self.seen = []

        def handler(body):
            self.seen.append(body)
            if body == b"fail":
                raise RuntimeError("handler")
            return b"\xa0" + body
        self.server = OneShotServer(context=self.pki.server_context(self.HOST), client_pin=self.pki.client_pin,
                                    host=self.HOST, path=PLANNER_PATH, handler=handler, timeout=5).start()

    def tearDown(self):
        self.server.close()

    def exchange(self, header, body, *, identity=None, certificate=True):
        context = _client_context(self.pki, identity=identity, certificate=certificate)
        with socket.create_connection(self.server.address, timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=self.HOST) as tls:
                tls.sendall(header + body)
                received = bytearray()
                while True:
                    part = tls.recv(65536)
                    if not part:
                        return bytes(received)
                    received.extend(part)

    def test_agentd_request_gets_the_exact_response_and_a_clean_close(self):
        body = b"\x84\x02"
        reply = self.exchange(request_header(PLANNER_PATH, self.server.authority, len(body)), body)
        self.assertEqual(reply, response_bytes(b"\xa0" + body))
        self.assertTrue(reply.startswith(b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 3\r\n"))
        self.assertTrue(self.server.settled())
        self.assertEqual((self.server.served, self.seen), (1, [body]))

    def test_a_port_a_provider_listens_on_is_never_taken(self):
        # The release provider's fixed port lies in the ephemeral range: a
        # server that drew it closes that listener and takes another port.
        from unittest import mock
        from savana_bench import structured_wire
        created = []

        class Socket(socket.socket):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)

            def getsockname(self):
                name = super().getsockname()
                return (name[0], 43191) if self is created[0] else name
        with mock.patch.object(structured_wire.socket, "socket", Socket):
            server = OneShotServer(context=self.pki.server_context(self.HOST), client_pin=self.pki.client_pin,
                                   host=self.HOST, path=PLANNER_PATH, handler=lambda body: body, avoid={43191})
        try:
            self.assertEqual(len(created), 2)
            self.assertEqual(created[0].fileno(), -1)
            self.assertNotEqual(server.address[1], 43191)
        finally:
            server.close()

    def test_any_other_request_or_client_gets_no_reply(self):
        body = b"\x84\x02"
        exact = request_header(PLANNER_PATH, self.server.authority, len(body))
        for header in (request_header(MAPPER_PATH, self.server.authority, len(body)),
                       request_header(PLANNER_PATH, self.HOST, len(body)),
                       exact.replace(b"Connection: close", b"Connection: keep-alive"),
                       exact.replace(b"\r\n\r\n", b"\r\nX-Extra: 1\r\n\r\n"),
                       exact.replace(b"Content-Length: 2", b"Content-Length: 02")):
            with self.subTest(header=header):
                try:
                    self.assertEqual(self.exchange(header, body), b"")
                except (ssl.SSLError, OSError):
                    pass
        self.assertEqual(self.exchange(request_header(PLANNER_PATH, self.server.authority, 4), b"fail"), b"")
        for identity, certificate in ((None, False), (self.other, True)):
            try:
                self.assertEqual(self.exchange(exact, body, identity=identity, certificate=certificate), b"")
            except (ssl.SSLError, OSError):
                pass
        self.assertTrue(self.server.settled())
        self.assertEqual((self.server.served, self.server.rejected), (0, 8))
        self.assertEqual(self.seen, [b"fail"])


if __name__ == "__main__":
    unittest.main()
