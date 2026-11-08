import json
import re
import unicodedata
from typing import Generator, Tuple, List, Optional
from dual_view_stream import QuadViewStreamProtector, SecurityError

class SSEProtocolError(Exception):
    pass

class IncrementalJSONUnescaper:
    OUT = 0
    IN_STR = 1
    ESC = 2
    U0, U1, U2, U3 = 3, 4, 5, 6
    HI_PENDING = 7
    HI_ESC = 8
    HI_U0, HI_U1, HI_U2, HI_U3 = 9, 10, 11, 12

    def __init__(self):
        self.state = self.OUT
        self.hex_acc = 0
        self.hi_surrogate = 0
        self.raw_acc = []

    def feed(self, chunk: str) -> Generator[Tuple[str, str], None, None]:
        for ch in chunk:
            self.raw_acc.append(ch)
            s = self.state

            if s == self.OUT:
                if ch == '"':
                    self.state = self.IN_STR
                    raw = "".join(self.raw_acc)
                    self.raw_acc = []
                    yield ('"', raw)
                else:
                    raw = "".join(self.raw_acc)
                    self.raw_acc = []
                    yield (ch, raw)

            elif s == self.IN_STR:
                if ch == '"':
                    self.state = self.OUT
                    raw = "".join(self.raw_acc)
                    self.raw_acc = []
                    yield ('"', raw)
                elif ch == '\\':
                    self.state = self.ESC
                else:
                    if ord(ch) < 0x20:
                        raise SSEProtocolError(f"Raw control char 0x{ord(ch):02x} inside JSON string")
                    raw = "".join(self.raw_acc)
                    self.raw_acc = []
                    yield (ch, raw)

            elif s == self.ESC:
                simple_escapes = {'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}
                if ch in simple_escapes:
                    self.state = self.IN_STR
                    raw = "".join(self.raw_acc)
                    self.raw_acc = []
                    yield (simple_escapes[ch], raw)
                elif ch == 'u':
                    self.hex_acc = 0
                    self.state = self.U0
                else:
                    raise SSEProtocolError(f"Invalid escape character: \\{ch}")

            elif s in (self.U0, self.U1, self.U2, self.U3):
                if not (('0' <= ch <= '9') or ('a' <= ch <= 'f') or ('A' <= ch <= 'F')):
                    raise SSEProtocolError(f"Non-hex char in \\u escape: {ch}")
                self.hex_acc = (self.hex_acc << 4) | int(ch, 16)
                if s == self.U0: self.state = self.U1
                elif s == self.U1: self.state = self.U2
                elif s == self.U2: self.state = self.U3
                elif s == self.U3:
                    val = self.hex_acc
                    if 0xD800 <= val <= 0xDBFF:
                        self.hi_surrogate = val
                        self.state = self.HI_PENDING
                    elif 0xDC00 <= val <= 0xDFFF:
                        raise SSEProtocolError("Unpaired low surrogate")
                    else:
                        self.state = self.IN_STR
                        raw = "".join(self.raw_acc)
                        self.raw_acc = []
                        yield (chr(val), raw)

            elif s == self.HI_PENDING:
                if ch == '\\':
                    self.state = self.HI_ESC
                else:
                    raise SSEProtocolError("Lone high surrogate not followed by escape")

            elif s == self.HI_ESC:
                if ch == 'u':
                    self.hex_acc = 0
                    self.state = self.HI_U0
                else:
                    raise SSEProtocolError("Lone high surrogate not followed by \\u escape")

            elif s in (self.HI_U0, self.HI_U1, self.HI_U2, self.HI_U3):
                if not (('0' <= ch <= '9') or ('a' <= ch <= 'f') or ('A' <= ch <= 'F')):
                    raise SSEProtocolError(f"Non-hex char in surrogate \\u escape: {ch}")
                self.hex_acc = (self.hex_acc << 4) | int(ch, 16)
                if s == self.HI_U0: self.state = self.HI_U1
                elif s == self.HI_U1: self.state = self.HI_U2
                elif s == self.HI_U2: self.state = self.HI_U3
                elif s == self.HI_U3:
                    lo = self.hex_acc
                    if not (0xDC00 <= lo <= 0xDFFF):
                        raise SSEProtocolError("Invalid low surrogate in pair")
                    astral_code = 0x10000 + ((self.hi_surrogate - 0xD800) << 10) + (lo - 0xDC00)
                    self.state = self.IN_STR
                    raw = "".join(self.raw_acc)
                    self.raw_acc = []
                    yield (chr(astral_code), raw)

    def finalize(self):
        if self.state != self.OUT:
            raise SSEProtocolError(f"Incomplete JSON document at stream boundary (state={self.state})")


class SSEStreamGateway:
    MAX_EVENT_BYTES = 65536
    ALLOWED_EVENT_TYPES = {
        "ping", "message_start", "content_block_start", 
        "content_block_delta", "content_block_stop", 
        "message_delta", "message_stop"
    }
    ALLOWED_STOP_REASONS = {"end_turn", "max_tokens", "stop_sequence", "tool_use", "pause_turn", "refusal", None}
    TOOL_NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')

    def __init__(self, protector: QuadViewStreamProtector):
        self.protector = protector
        self.unescaper = IncrementalJSONUnescaper()
        self.byte_buf = bytearray()
        self.queue = []
        self.active_block_index = 0
        self.latched_closed = False
        self.cleared_tokens_count = 0

    def feed_bytes(self, data: bytes) -> List[str]:
        if self.latched_closed:
            return []

        self.byte_buf.extend(data)
        out_events = []

        try:
            while True:
                patterns = [
                    (b"\r\n\r\n", 4),
                    (b"\n\r\n", 3),
                    (b"\r\n\r", 3),
                    (b"\n\n", 2),
                    (b"\r\r", 2)
                ]

                candidates = []
                for pat, plen in patterns:
                    pos = self.byte_buf.find(pat)
                    if pos != -1:
                        candidates.append((pos, plen))

                if not candidates:
                    if len(self.byte_buf) > self.MAX_EVENT_BYTES:
                        self.latched_closed = True
                        raise SSEProtocolError(f"MAX_EVENT_BYTES ({self.MAX_EVENT_BYTES}) exceeded")
                    break

                candidates.sort(key=lambda x: x[0])
                boundary, sep_len = candidates[0]

                if boundary > self.MAX_EVENT_BYTES:
                    self.latched_closed = True
                    raise SSEProtocolError(f"Event size {boundary} exceeds MAX_EVENT_BYTES")

                event_bytes = self.byte_buf[:boundary]
                del self.byte_buf[:boundary + sep_len]

                try:
                    event_str = event_bytes.decode('utf-8')
                except UnicodeDecodeError as e:
                    self.latched_closed = True
                    raise SSEProtocolError(f"Strict UTF-8 decode failed: {e}")

                emitted = self._process_sse_event_string(event_str)
                if emitted:
                    out_events.extend(emitted)

        except (SecurityError, SSEProtocolError):
            self.latched_closed = True
            raise
        except Exception as e:
            self.latched_closed = True
            raise SSEProtocolError(f"Internal gateway fault: {e}")

        return out_events

    def _process_sse_event_string(self, event_str: str) -> List[str]:
        data_lines = []
        raw_lines = re.split(r'\r\n|\r|\n', event_str)
        for line in raw_lines:
            if not line or line.startswith(':'):
                continue
            if line.startswith('data:'):
                data_lines.append(line[5:].lstrip(' '))

        if not data_lines:
            return []

        payload = "\n".join(data_lines)
        try:
            ev_json = json.loads(payload)
        except json.JSONDecodeError as e:
            raise SSEProtocolError(f"Malformed event JSON: {e}")

        if not isinstance(ev_json, dict):
            raise SSEProtocolError("Event JSON is not an object")

        ev_type = ev_json.get("type")
        if not isinstance(ev_type, str) or '\r' in ev_type or '\n' in ev_type:
            raise SSEProtocolError("Invalid or header-injected event type")
        if ev_type not in self.ALLOWED_EVENT_TYPES:
            raise SSEProtocolError(f"Disallowed event type: {ev_type}")

        if ev_type == "message_start":
            msg_obj = ev_json.get("message")
            if not isinstance(msg_obj, dict):
                raise SSEProtocolError("message_start missing message object")
            clean_msg = {
                "id": str(msg_obj.get("id", "")),
                "type": "message",
                "role": "assistant",
                "model": str(msg_obj.get("model", "")),
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": msg_obj.get("usage", {"input_tokens": 0, "output_tokens": 0})
            }
            clean_ev = {"type": "message_start", "message": clean_msg}
            self._scan_envelope_for_canary(clean_ev)
            self.queue.append(('CTRL', ev_type, self._canon_event("message_start", clean_ev)))

        elif ev_type == "content_block_start":
            raw_idx = ev_json.get("index", 0)
            if not isinstance(raw_idx, int) or raw_idx < 0:
                raise SSEProtocolError("Invalid content_block index")
            self.active_block_index = raw_idx
            cb_obj = ev_json.get("content_block")
            if not isinstance(cb_obj, dict): cb_obj = {"type": "text"}

            cb_type = cb_obj.get("type")
            clean_cb = {"type": cb_type}
            if cb_type == "tool_use":
                t_name = cb_obj.get("name", "")
                if not isinstance(t_name, str) or (t_name and not self.TOOL_NAME_RE.match(t_name)):
                    raise SSEProtocolError(f"Invalid tool name: {t_name}")
                clean_cb["name"] = t_name
                clean_cb["id"] = str(cb_obj.get("id", ""))
                clean_cb["input"] = {}
            elif cb_type == "thinking":
                clean_cb["thinking"] = ""
            elif cb_type == "text":
                clean_cb["text"] = ""
            else:
                raise SSEProtocolError(f"Disallowed content_block type: {cb_type}")

            clean_ev = {"type": "content_block_start", "index": self.active_block_index, "content_block": clean_cb}
            self._scan_envelope_for_canary(clean_ev)
            self.queue.append(('CTRL', ev_type, self._canon_event("content_block_start", clean_ev)))

        elif ev_type == "content_block_delta":
            delta = ev_json.get("delta")
            if not isinstance(delta, dict):
                raise SSEProtocolError("delta must be an object")
            d_type = delta.get("type")
            raw_idx = ev_json.get("index", self.active_block_index)
            if not isinstance(raw_idx, int) or raw_idx < 0:
                raise SSEProtocolError("Invalid delta index")

            if d_type in ("text_delta", "thinking_delta"):
                key = "text" if d_type == "text_delta" else "thinking"
                text_val = delta.get(key)
                if not isinstance(text_val, str):
                    raise SSEProtocolError("delta content must be string")
                for c in text_val:
                    if unicodedata.category(c) == 'Cs':
                        raise SSEProtocolError(f"Lone surrogate U+{ord(c):04X}")
                    emitted = self.protector.process_chunk(c)
                    self.queue.append(('DATA', c, raw_idx, d_type, c))
                    if emitted:
                        self.cleared_tokens_count += len(emitted)

            elif d_type == "input_json_delta":
                partial_json = delta.get("partial_json")
                if not isinstance(partial_json, str):
                    raise SSEProtocolError("partial_json must be string")
                for dec_ch, raw_span in self.unescaper.feed(partial_json):
                    if unicodedata.category(dec_ch) == 'Cs':
                        raise SSEProtocolError("Lone surrogate in tool input")
                    emitted = self.protector.process_chunk(dec_ch)
                    self.queue.append(('DATA', dec_ch, raw_idx, d_type, raw_span))
                    if emitted:
                        self.cleared_tokens_count += len(emitted)

            elif d_type == "citations_delta":
                citation = delta.get("citation")
                if not isinstance(citation, dict):
                    raise SSEProtocolError("citation must be an object")
                cited_text = citation.get("cited_text", "")
                if not isinstance(cited_text, str):
                    raise SSEProtocolError("cited_text must be string")

                safe_citation = {
                    "type": str(citation.get("type", "char_location")),
                    "cited_text": cited_text,
                    "document_index": int(citation.get("document_index", 0)),
                    "document_title": str(citation.get("document_title", ""))[:128],
                    "start_char_index": int(citation.get("start_char_index", 0)),
                    "end_char_index": int(citation.get("end_char_index", 0))
                }
                self._scan_envelope_for_canary({"title": safe_citation["document_title"]})

                for c in cited_text:
                    if unicodedata.category(c) == 'Cs':
                        raise SSEProtocolError("Lone surrogate in cited_text")
                    emitted = self.protector.process_chunk(c)
                    self.queue.append(('DATA', c, raw_idx, "citation_char", c))
                    if emitted:
                        self.cleared_tokens_count += len(emitted)

                clean_delta = {"type": "citations_delta", "citation": safe_citation}
                self.queue.append(('CTRL_CITATION', raw_idx, len(cited_text), self._canon_event("content_block_delta", {"type": "content_block_delta", "index": raw_idx, "delta": clean_delta})))

            elif d_type == "signature_delta":
                sig = delta.get("signature")
                if not isinstance(sig, str) or len(sig) > 4096 or not re.match(r'^[A-Za-z0-9+/=_-]*$', sig):
                    raise SSEProtocolError("Invalid signature format")
                self._scan_envelope_for_canary({"sig": sig})
                clean_delta = {"type": "signature_delta", "signature": sig}
                self.queue.append(('CTRL', "content_block_delta", self._canon_event("content_block_delta", {"type": "content_block_delta", "index": raw_idx, "delta": clean_delta})))
            else:
                raise SSEProtocolError(f"Disallowed delta type: {d_type}")

            self._assert_buffer_queue_invariant()

        elif ev_type == "content_block_stop":
            raw_idx = ev_json.get("index", self.active_block_index)
            if not isinstance(raw_idx, int) or raw_idx < 0:
                raise SSEProtocolError("Invalid content_block_stop index")
            self.unescaper.finalize()
            clean_ev = {"type": "content_block_stop", "index": raw_idx}
            self.queue.append(('CTRL', ev_type, self._canon_event("content_block_stop", clean_ev)))

        elif ev_type == "message_delta":
            delta_obj = ev_json.get("delta")
            if not isinstance(delta_obj, dict):
                raise SSEProtocolError("message_delta must have delta object")
            stop_reason = delta_obj.get("stop_reason")
            if stop_reason not in self.ALLOWED_STOP_REASONS:
                raise SSEProtocolError(f"Disallowed stop_reason: {stop_reason}")

            clean_delta = {"stop_reason": stop_reason, "stop_sequence": delta_obj.get("stop_sequence")}
            clean_ev = {"type": "message_delta", "delta": clean_delta}
            if "usage" in ev_json and isinstance(ev_json["usage"], dict):
                clean_ev["usage"] = {"output_tokens": int(ev_json["usage"].get("output_tokens", 0))}
            self._scan_envelope_for_canary(clean_ev)
            self.queue.append(('CTRL', ev_type, self._canon_event("message_delta", clean_ev)))

        elif ev_type == "message_stop":
            flushed = self.protector.flush()
            if flushed:
                self.cleared_tokens_count += len(flushed)
            clean_ev = {"type": "message_stop"}
            self.queue.append(('CTRL', ev_type, self._canon_event("message_stop", clean_ev)))
            res = self._drain_all()
            self.cleared_tokens_count = 0
            self._assert_buffer_queue_invariant()
            return res

        elif ev_type == "ping":
            self.queue.append(('CTRL', ev_type, self._canon_event("ping", {"type": "ping"})))

        return self._drain_in_order()

    def _assert_buffer_queue_invariant(self):
        if self.cleared_tokens_count < 0:
            self.latched_closed = True
            raise SecurityError("Desync: cleared_tokens_count is negative")
        pending_data_count = sum(1 for item in self.queue if item[0] == 'DATA')
        held_in_queue = pending_data_count - self.cleared_tokens_count
        buf_len = len(getattr(self.protector, 'raw_buffer', []))
        if hasattr(self.protector, 'raw_buffer') and held_in_queue != buf_len:
            self.latched_closed = True
            raise SecurityError(f"Desync detected: Queue DATA ({held_in_queue}) != Protector buffer ({buf_len})")

    def _scan_envelope_for_canary(self, obj: dict):
        dumped = json.dumps(obj)
        for v in getattr(self.protector, 'variants', []):
            if v.lower() in dumped.lower():
                raise SecurityError("Canary detected in envelope structure")

    def _drain_in_order(self) -> List[str]:
        events = []
        while self.queue:
            item = self.queue[0]
            if item[0] == 'CTRL':
                events.append(self.queue.pop(0)[2])
            elif item[0] == 'CTRL_CITATION':
                events.append(item[3])
                self.queue.pop(0)
            elif item[0] == 'DATA':
                if self.cleared_tokens_count <= 0:
                    break
                run_idx = item[2]
                run_kind = item[3]
                data_run = []
                while self.queue and self.queue[0][0] == 'DATA' and self.cleared_tokens_count > 0:
                    next_d = self.queue[0]
                    if next_d[2] == run_idx and next_d[3] == run_kind:
                        data_run.append(self.queue.pop(0))
                        self.cleared_tokens_count -= 1
                    else:
                        break
                if data_run and run_kind != "citation_char":
                    raw_text = "".join(d[4] for d in data_run)
                    events.append(self._make_delta_event(run_idx, run_kind, raw_text))
        return events

    def _drain_all(self) -> List[str]:
        self.cleared_tokens_count = 1000000000
        return self._drain_in_order()

    @staticmethod
    def _make_delta_event(index: int, delta_kind: str, raw_text: str) -> str:
        if delta_kind == "input_json_delta":
            delta_obj = {"type": "input_json_delta", "partial_json": raw_text}
        elif delta_kind == "thinking_delta":
            delta_obj = {"type": "thinking_delta", "thinking": raw_text}
        else:
            delta_obj = {"type": "text_delta", "text": raw_text}

        ev_dict = {
            "type": "content_block_delta",
            "index": index,
            "delta": delta_obj
        }
        return f"event: content_block_delta\ndata: {json.dumps(ev_dict, separators=(',', ':'))}\n\n"

    @staticmethod
    def _canon_event(event_type: str, data_dict: dict) -> str:
        return f"event: {event_type}\ndata: {json.dumps(data_dict, separators=(',', ':'))}\n\n"
