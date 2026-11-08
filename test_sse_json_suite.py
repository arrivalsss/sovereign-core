import json
import secrets
from sse_json_layer import IncrementalJSONUnescaper, SSEStreamGateway, SSEProtocolError
from dual_view_stream import QuadViewStreamProtector, SecurityError
from test_canary_h_table import generate_variants_table

CANARY = "deadbeef12345678deadbeef12345678"
variants_dict, H = generate_variants_table(CANARY)

print("=== 1. Surrogate Pairs & Astral Tag Decoding Test ===")
unesc = IncrementalJSONUnescaper()
tag_pair_str = r'"prefix\udb40\udc78suffix"'
decoded_chars = [c for c, _ in unesc.feed(tag_pair_str)]
unesc.finalize()
decoded_str = "".join(decoded_chars)
print(f"Decoded: {repr(decoded_str)}")
assert chr(0xE0078) in decoded_str, "Failed to decode surrogate pair to astral code point U+E0078!"
print("  [PASS] Astral surrogate pair atomically decoded.\n")

print("=== 2. Lone Surrogate Fail-Closed Verification ===")
unesc_lone = IncrementalJSONUnescaper()
lone_caught = False
try:
    for _ in unesc_lone.feed(r'"invalid\ud800not_surrogate"'): pass
except SSEProtocolError:
    lone_caught = True
print(f"Lone High Surrogate Caught: {lone_caught}")
assert lone_caught == True, "Failed to reject lone surrogate!"
print("  [PASS] Lone surrogate rejected with fail-closed.\n")

print("=== 3. Canary Delivered as \\u00XX Escapes in input_json_delta ===")
u_escaped_canary = "".join(f"\\u00{ord(c):02x}" for c in CANARY)
prot = QuadViewStreamProtector(CANARY, variants_dict)
gw = SSEStreamGateway(prot)

event1 = f'data: {{"type":"content_block_start","index":0}}\n\n'.encode('utf-8')
event2 = f'data: {{"type":"content_block_delta","index":0,"delta":{{"type":"input_json_delta","partial_json":"\\"{u_escaped_canary}\\""}}}}\n\n'.encode('utf-8')

gw.feed_bytes(event1)
blocked_u = False
try:
    gw.feed_bytes(event2)
except SecurityError:
    blocked_u = True
print(f"Canary in \\u00XX Escapes Blocked: {blocked_u}")
assert blocked_u == True, "Failed to block canary delivered via \\u00XX escapes in input_json_delta!"
print("  [PASS] Tool-input incremental unescaper caught \\u00XX canary.\n")

print("=== 4. Cross-Block Canary (text_delta -> input_json_delta) ===")
half1 = CANARY[:16]
half2 = CANARY[16:]
prot_cross = QuadViewStreamProtector(CANARY, variants_dict)
gw_cross = SSEStreamGateway(prot_cross)

ev_b0_start = b'data: {"type":"content_block_start","index":0}\n\n'
ev_b0_delta = f'data: {{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"prefix_{half1}"}}}}\n\n'.encode('utf-8')
ev_b0_stop = b'data: {"type":"content_block_stop","index":0}\n\n'

ev_b1_start = b'data: {"type":"content_block_start","index":1}\n\n'
ev_b1_delta = f'data: {{"type":"content_block_delta","index":1,"delta":{{"type":"input_json_delta","partial_json":"\\"{half2}_suffix\\""}}}}\n\n'.encode('utf-8')

gw_cross.feed_bytes(ev_b0_start)
gw_cross.feed_bytes(ev_b0_delta)
gw_cross.feed_bytes(ev_b0_stop)
gw_cross.feed_bytes(ev_b1_start)

blocked_cross = False
try:
    gw_cross.feed_bytes(ev_b1_delta)
except SecurityError:
    blocked_cross = True

print(f"Cross-Block Canary Blocked: {blocked_cross}")
assert blocked_cross == True, "Failed to catch canary spanning across text and tool_use blocks!"
print("  [PASS] Cross-block persistence confirmed: no flush at content_block_stop.\n")

print("=== 5. Invariant I1: Chunking Invariance at 1-Byte TCP Slices ===")
msg = b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Safe streaming response."}}\n\ndata: {"type":"message_stop"}\n\n'
prot_single = QuadViewStreamProtector(CANARY, variants_dict)
gw_single = SSEStreamGateway(prot_single)
res_single = gw_single.feed_bytes(msg)

prot_byte = QuadViewStreamProtector(CANARY, variants_dict)
gw_byte = SSEStreamGateway(prot_byte)
res_byte = []
for b in msg:
    out = gw_byte.feed_bytes(bytes([b]))
    if out: res_byte.extend(out)

assert len(res_single) == len(res_byte), "Chunking invariance violated!"
print("  [PASS] I1 Chunking invariance verified across 1-byte splits.\n")

print("=== ALL SSE/JSON SPECIFICATION SUITES VERIFIED (0 FAILURES) ===")
