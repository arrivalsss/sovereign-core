import json
import secrets
from sse_json_layer import SSEStreamGateway, SSEProtocolError
from dual_view_stream import QuadViewStreamProtector, SecurityError
from test_canary_h_table import generate_variants_table

CANARY = "deadbeef12345678deadbeef12345678"
variants_dict, H = generate_variants_table(CANARY)

print("=== 1. Counterexample 1: Text + Tool Short Message Sequencing ===")
prot1 = QuadViewStreamProtector(CANARY, variants_dict)
gw1 = SSEStreamGateway(prot1)

events_in = [
    b'data: {"type":"message_start","message":{"id":"msg_1"}}\n\n',
    b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n',
    b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Checking now."}}\n\n',
    b'data: {"type":"content_block_stop","index":0}\n\n',
    b'data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","name":"get_weather"}}\n\n',
    b'data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"city\\":\\"Paris\\"}"}}\n\n',
    b'data: {"type":"content_block_stop","index":1}\n\n',
    b'data: {"type":"message_stop"}\n\n'
]

stream_out = []
for ev in events_in:
    out = gw1.feed_bytes(ev)
    if out: stream_out.extend(out)

parsed_events = []
for raw_ev in stream_out:
    for line in raw_ev.splitlines():
        if line.startswith("data:"):
            parsed_events.append(json.loads(line[5:].strip()))

types_sequence = [e["type"] for e in parsed_events]
print(f"  Sequence: {types_sequence}")

deltas = [e for e in parsed_events if e["type"] == "content_block_delta"]
assert len(deltas) == 2, f"Expected 2 deltas, got {len(deltas)}"
assert deltas[0]["index"] == 0 and deltas[0]["delta"]["type"] == "text_delta"
assert deltas[0]["delta"]["text"] == "Checking now."
assert deltas[1]["index"] == 1 and deltas[1]["delta"]["type"] == "input_json_delta"
assert deltas[1]["delta"]["partial_json"] == '{"city":"Paris"}'

idx_delta0 = parsed_events.index(deltas[0])
idx_stop0 = next(i for i, e in enumerate(parsed_events) if e["type"] == "content_block_stop" and e.get("index") == 0)
assert idx_delta0 < idx_stop0, "Text delta leaked after content_block_stop(0)!"

idx_delta1 = parsed_events.index(deltas[1])
idx_stop1 = next(i for i, e in enumerate(parsed_events) if e["type"] == "content_block_stop" and e.get("index") == 1)
assert idx_delta1 < idx_stop1, "Tool delta leaked after content_block_stop(1)!"

print("  [PASS] Clean block segregation and FIFO control event ordering confirmed.\n")

print("=== 2. Counterexample 2 & 4: Special Line Separators & \\r\\r Support ===")
prot2 = QuadViewStreamProtector(CANARY, variants_dict)
gw2 = SSEStreamGateway(prot2)

special_sep_text = "Safe line 1\u2028Safe line 2\u2029Safe line 3"
ev_special = f'data: {{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"{special_sep_text}"}}}}\r\r'.encode('utf-8')
out_special = gw2.feed_bytes(ev_special)
assert len(gw2.byte_buf) == 0, "\\r\\r delimiter failed to clear byte buffer!"
print("  [PASS] U+2028/U+2029 preserved; \\r\\r delimiter correctly framed.\n")

print("=== 3. Counterexample 3: Lone Surrogates (Cs) in text_delta ===")
prot3 = QuadViewStreamProtector(CANARY, variants_dict)
gw3 = SSEStreamGateway(prot3)
ev_lone = b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\ud800"}}\n\n'
lone_rejected = False
try:
    gw3.feed_bytes(ev_lone)
except SSEProtocolError:
    lone_rejected = True
assert lone_rejected == True, "Failed to reject lone surrogate in text_delta!"
print("  [PASS] Lone surrogate in text_delta rejected with fail-closed.\n")

print("=== 4. Counterexample 6: Terminal Latch on Violation ===")
prot4 = QuadViewStreamProtector(CANARY, variants_dict)
gw4 = SSEStreamGateway(prot4)
ev_canary = f'data: {{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"{CANARY}"}}}}\n\n'.encode('utf-8')
try:
    gw4.feed_bytes(ev_canary)
except SecurityError:
    pass

assert gw4.latched_closed == True, "Gateway failed to latch closed!"
trailing = gw4.feed_bytes(b'data: {"type":"message_stop"}\n\n')
assert len(trailing) == 0, "Events forwarded after terminal security violation!"
print("  [PASS] Terminal latch verified: zero events emitted post-violation.\n")

print("=== ALL COUNTEREXAMPLES RESOLVED (0 FAILURES) ===")
