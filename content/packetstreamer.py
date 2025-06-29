import asyncio
import json
from scapy.all import AsyncSniffer, Packet, Raw
from scapy.layers.inet import TCP

import packetparser

SEQ_MOD = 2**32

def seq_distance(a, b):
    return ((a - b + 2**31) % 2**32) - 2**31

class PacketStreamer:
    _MAX_BUF = 16_384  
    _SEQ_GAP_RESET = 10_000
    
    def __init__(self, filter_expr: str = "tcp and src port 16000"):
        self.parser = packetparser.PacketParser()
        self.queue: asyncio.Queue[Packet] = asyncio.Queue()
        self.sniffer = AsyncSniffer(filter=filter_expr, prn=self._enqueue_packet)
        self.loop = asyncio.get_event_loop()
        self.buffer:bytes = b''
        self.tcp_segments = {}
        self.current_seq = None

    async def stream(self, websocket) -> None:
        self.sniffer.start()
        consumer_task = asyncio.create_task(self._process_packet(websocket))
        try:
            await websocket.wait_closed()
        finally:
            consumer_task.cancel()
            self.sniffer.stop()
            self.sniffer.join()            

    async def send_skill_mapping(self, websocket) -> None:
        import json
        with open('content/skills.json', 'r', encoding='utf-8') as f:
            data = json.load(f)  # 파일 → 딕셔너리
            await websocket.send(json.dumps({"type": "skill", "data": data}))

    def _enqueue_packet(self, pkt: Packet) -> None:
        self.loop.call_soon_threadsafe(self.queue.put_nowait, pkt)
        
    def _trim_buffer(self) -> None:
        if len(self.buffer) > self._MAX_BUF:
            self.buffer = self.buffer[len(self.buffer)//2:]
            print("Buffer trimmed to half")
            
    def _reset_on_seq_gap(self, seq):
        if abs(seq_distance(seq, self.current_seq)) > self._SEQ_GAP_RESET:
            print(f"Resetting due to large sequence gap: {seq} (current: {self.current_seq})")
            self.tcp_segments.clear()
            self.current_seq = None
            self.buffer = b''
            return True
        return False
    
    def _update_segments(self, seq, payload):
        if self.current_seq is None:
            self.current_seq = seq
            
        if seq not in self.tcp_segments or self.tcp_segments[seq] != payload:
            self.tcp_segments[seq] = payload

        if self.current_seq not in self.tcp_segments:
            print(f"Missing segment for current sequence: {self.current_seq}, current is {seq}")

    def _drain_segments(self):
        while self.current_seq in self.tcp_segments:
            segment = self.tcp_segments.pop(self.current_seq)
            self.buffer += segment
            self.current_seq = (self.current_seq + len(segment)) % SEQ_MOD
        
    
    async def _process_packet(self, websocket) -> None:
        while True:
            try:
                pkt: Packet = await self.queue.get()
            except asyncio.CancelledError as e:
                print(f"Packet processing cancelled: {e}")
                break

            if pkt.haslayer(Raw):
                seq = pkt[TCP].seq
                payload = bytes(pkt[Raw].load)
                
                self._update_segments(seq, payload)
                
                if self._reset_on_seq_gap(seq):
                    continue

                self._drain_segments()

                self._trim_buffer()

                parsed, pivot = self.parser.packet_parser(self.buffer)
                self.buffer = self.buffer[pivot:]

                if parsed:
                    try:
                        msg = json.dumps({"type": "json", "data": parsed})
                        await websocket.send(msg)
                    except Exception as e:
                        print(f"Error sending WebSocket message: {e}")
                        break