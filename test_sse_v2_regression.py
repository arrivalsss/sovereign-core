import json
import secrets
from sse_json_layer import SSEStreamGateway, SSEProtocolError
from dual_view_stream import QuadViewStreamProtector, SecurityError
from test_canary_h_table import generate_variants_table

CANARY = "deadbeef12345678deadbeef12345678"
variants_dict, H = generate_variants_table(CANARY)

print("=== 1. Multi-Char Event Chunk Fidelity Test (No Dropped Chars) ===")
sample_507 = ("Alpha Beta Gamma Delta Epsilon Zeta Eta Theta Iota Kappa Lambda Mu " * 8)[:507]
chunk_sizes = [1, 2, 5, 8, 25, 48]

for sz in chunk_sizes:
    prot = QuadViewStreamProtector(CANARY, variants_dict)
    gw = SSEStreamGateway(prot)
    
    events = [b'data: {"type":"content_block_start","index":0}\n\n']
    for i in range(0, len(sample_507), sz):
        slice_txt = sample_507[i:i+sz]
        ev_json = {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": slice_txt}}
        events.append(f"data: {json.dumps(ev_json)}\n\n".encode('utf-8'))
    events.append(b'data: {"type":"content_block_stop","index":0}\n\n')
    events.append(b'data: {"type":"message_stop"}\n\n')
    
    out_events = []
    for ev in events:
        res = gw.feed_bytes(ev)
        if res: out_events.extend(res)
        
    emitted_text = ""
    for raw in out_events:
        for line in raw.splitlines():
            if line.startswith("data:"):
                d = json.loads(line[5:].strip())
                if d.get("type") == "content_block_delta":
                    emitted_text += d["delta"].get("text", "")
                    
    print(f"  Chunk Size {sz:2d}: Input={len(sample_507)} | Emitted={len(emitted_text)}")
    assert emitted_text == sample_507, f"Fidelity loss at chunk size {sz}! Diff: {len(sample_507) - len(emitted_text)}"

print("  [PASS] 100% Fidelity verified across all multi-char chunk sizes.\n")

print("=== 2. Tool Input JSON No-Distortion & Strict Length Test ===")
sample_json_443 = json.dumps({"command": "analyze_payload", "parameters": {"iterations": 50, "target": "https://api.internal/v1/resource", "flags": ["strict", "audit", "liveness"], "meta": "benchmark testing string for length preservation without generator leak"}}, separators=(',', ':'))
print(f"Target Tool Input Length: {len(sample_json_443)}")

for t_sz in [1, 3, 48]:
    prot = QuadViewStreamProtector(CANARY, variants_dict)
    gw = SSEStreamGateway(prot)
    
    events = [b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use"}}\n\n']
    for i in range(0, len(sample_json_443), t_sz):
        slice_j = sample_json_443[i:i+t_sz]
        ev_json = {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": slice_j}}
        events.append(f"data: {json.dumps(ev_json)}\n\n".encode('utf-8'))
    events.append(b'data: {"type":"content_block_stop","index":0}\n\n')
    events.append(b'data: {"type":"message_stop"}\n\n')
    
    out_events = []
    for ev in events:
        res = gw.feed_bytes(ev)
        if res: out_events.extend(res)
        
    emitted_json = ""
    for raw in out_events:
        for line in raw.splitlines():
            if line.startswith("data:"):
                d = json.loads(line[5:].strip())
                if d.get("type") == "content_block_delta":
                    emitted_json += d["delta"].get("partial_json", "")
                    
    print(f"  Tool Chunk {t_sz:2d}: Input={len(sample_json_443)} | Emitted={len(emitted_json)}")
    assert emitted_json == sample_json_443, f"JSON distortion/expansion at chunk {t_sz}!"

print("  [PASS] Tool input JSON fidelity verified (Zero inflation, zero leak).\n")

print("=== 3. Mixed Delimiters (\\n\\r\\n and \\r\\n\\r) Support ===")
prot_delim = QuadViewStreamProtector(CANARY, variants_dict)
gw_delim = SSEStreamGateway(prot_delim)

ev_mixed = b'data: {"type":"ping"}\n\r\ndata: {"type":"ping"}\r\n\r'
out_delim = gw_delim.feed_bytes(ev_mixed)
print(f"Mixed Delimiters Emitted: {len(out_delim)} events | Buffer remaining: {len(gw_delim.byte_buf)}")
assert len(gw_delim.byte_buf) == 0, "Mixed delimiters failed to clear buffer!"
assert len(out_delim) == 2, f"Expected 2 ping events, got {len(out_delim)}"
print("  [PASS] Mixed delimiters cleanly parsed and cleared.\n")

print("=== 4. Strict Short Message Event Ordering (FIFO Queue) ===")
prot_seq = QuadViewStreamProtector(CANARY, variants_dict)
gw_seq = SSEStreamGateway(prot_seq)

short_flow = [
    b'data: {"type":"message_start","message":{"id":"msg_short"}}\n\n',
    b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text"}}\n\n',
    b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Checking now."}}\n\n',
    b'data: {"type":"content_block_stop","index":0}\n\n',
    b'data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","name":"get_weather"}}\n\n',
    b'data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"city\\":\\"Paris\\"}"}}\n\n',
    b'data: {"type":"content_block_stop","index":1}\n\n',
    b'data: {"type":"message_stop"}\n\n'
]

stream_res = []
for ev in short_flow:
    out = gw_seq.feed_bytes(ev)
    if out: stream_res.extend(out)

parsed_seq = []
for raw in stream_res:
    for line in raw.splitlines():
        if line.startswith("data:"):
            parsed_seq.append(json.loads(line[5:].strip()))

seq_summary = [(e["type"], e.get("index")) for e in parsed_seq]
print(f"Exact Sequence: {seq_summary}")

expected_types = [
    ("message_start", None),
    ("content_block_start", 0),
    ("content_block_delta", 0),
    ("content_block_stop", 0),
    ("content_block_start", 1),
    ("content_block_delta", 1),
    ("content_block_stop", 1),
    ("message_stop", None)
]
for idx, (exp_t, exp_i) in enumerate(expected_types):
    act_t, act_i = seq_summary[idx]
    assert act_t == exp_t, f"Step {idx}: expected {exp_t}, got {act_t}"
    if exp_i is not None:
        assert act_i == exp_i, f"Step {idx}: expected index {exp_i}, got {act_i}"

print("  [PASS] Strict FIFO control & data event ordering verified.\n")

print("=== ALL SSE v2 REGRESSION TESTS PASSED (0 FAILURES) ===")
