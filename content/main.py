import asyncio
import json
from functools import lru_cache
from websockets import serve
from scapy.all import AsyncSniffer, Packet, Raw
from scapy.layers.inet import TCP
import brotli

FLAG_BITS = (
    (0, 'crit_flag', 0x01),
    (0, 'what1', 0x02),
    (0, 'unguarded_flag', 0x04),
    (0, 'break_flag', 0x08),

    (0, 'what05', 0x10),
    (0, 'what06', 0x20),
    (0, 'first_hit_flag', 0x40),
    (0, 'default_attack_flag', 0x80),
    
    (1, 'multi_attack_flag', 0x01),
    (1, 'power_flag', 0x02),
    (1, 'fast_flag', 0x04),
    (1, 'dot_flag', 0x08),
    
    #(1, 'what15', 0x10),
    #(1, 'what16', 0x20),
    #(1, 'what17', 0x40),
    (1, 'dot_flag2', 0x80),

    (2, 'dot_flag3', 0x01),
    #(2, 'what22', 0x02),
    #(2, 'what23', 0x04),
    #(2, 'what24', 0x08),
    
    #(2, 'what25', 0x10),
    #(2, 'what26', 0x20),
    #(2, 'what27', 0x40),
    #(2, 'what28', 0x80),

    #(3, 'what31', 0x01),
    #(3, 'what32', 0x02),
    #(3, 'what33', 0x04),
    (3, 'add_hit_flag', 0x08),

    (3, 'bleed_flag', 0x10),
    (3, 'what46', 0x20),
    (3, 'fire_flag', 0x40),
    (3, 'holy_flag', 0x80),

    (4, 'ice_flag', 0x01),
    (4, 'electric_flag', 0x02),
    (4, 'poison_flag', 0x04),
    (4, 'mind_flag', 0x08),

    #(4, 'not_dot_flag', 0x10),
    #(4, 'what46', 0x20),
    #(4, 'what47', 0x40),
    #(4, 'what48', 0x80),
)

@lru_cache(maxsize=256)
def extract_flags(flags: bytes) -> dict:
    result = {}
    for index, name, mask in FLAG_BITS:
        result[name] = int((flags[index] & mask) != 0) if index < len(flags) else 0
    return result

def parse_damage(data):
    if len(data) != 35:
        print("parse damage data length is not 4")
        return ""

    pivot = 0

    user_id, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    b, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    target_id, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    d, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    action_id, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    f, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    flags, pivot =  data[pivot:pivot+7], pivot+7
    e, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4

    return {
        "type": 10299,
        "hide": False,
        "user_id": user_id,
        "target_id": target_id,
        "action_id": action_id,
        "flags": extract_flags(flags),
        "etc": f"b: {b}, d: {d}, f: {f}, e: {e}",
    }

def parse_action(data):
    pivot = 0

    user_id, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    e1, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4

    skill_name_len, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    skill_name, pivot =  data[pivot:pivot+skill_name_len], pivot+skill_name_len

    return {
        "type": 100041,
        "hide": False,
        "user_id": user_id,
        "skill_name": skill_name.replace(b'\x00', b'').decode('utf-8', errors='replace').strip(),
    }

def parse_hp_changed(data):
    pivot = 0

    target_id, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    a, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    
    prev, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    b, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4    

    current, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    c, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4

    return {
        "type": 100178,
        "target_id": target_id,
        "prev_hp": prev,
        "current_hp": current
    }

def parse_self_damage(data):
    if len(data) != 53:
        print("parse damage data length is not 4")
        return ""

    pivot = 0

    user_id, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    e1, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4

    target_id, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    e2, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    
    damage, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4

    return {
        "type": 10701,
        "hide": True,
        "user_id": user_id,
        "target_id": target_id,
        "damage": damage,
    }

parse_dict = {
    10299: parse_damage,
    100041: parse_action,      
    100178: parse_hp_changed,  # 체력 변화, (4 대상, 4 패딩, 4 기존, 4 패딩, 4 현재, 4패딩)
    10701: parse_self_damage,
    }

SEQ_MOD = 2**32

def seq_distance(a, b):
    return ((a - b + 2**31) % 2**32) - 2**31

class PacketStreamer:
    def __init__(self, filter_expr: str = "tcp and src port 16000"):
        self.queue: asyncio.Queue[Packet] = asyncio.Queue()
        self.sniffer = AsyncSniffer(filter=filter_expr, prn=self._enqueue_packet)
        self.loop = asyncio.get_event_loop()
        self.buffer:bytes = b''
        self.tcp_segments = {}
        self.current_seq = None

    async def stream(self, websocket) -> None:
        self.sniffer.start()
        consumer_task = asyncio.create_task(self._process(websocket))
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

    def _packet_parser(self, data: bytes) -> tuple[list,int]:
        res = []
        pivot = 0
        buffer_size = len(data)

        while(pivot < len(data)):
            
            # 패킷 시작 부분 찾기
            pivot = data.find(b'\x65\x27\x00\x00\x00\x00\x00\x00\x00', pivot)
            if pivot == -1:
                break
            # 패킷 끝 부분 찾기
            if data.find(b'\xe0\x27\x00\x00\x00\x00\x00\x00\x00', pivot + 9) == -1:
                break
            pivot += 9  # 패킷 시작 부분 이후로 이동

            # 패킷이 완전한지 확인
            while ( buffer_size > pivot + 9):

                # 데이터 타입, 길이, 인코딩 타입 추출
                data_type = int.from_bytes(data[pivot:pivot+4], byteorder='little')
                length = int.from_bytes(data[pivot+4:pivot+8], byteorder='little')
                encode_type = data[pivot+8]

                if data_type == 0:
                    break
                
                # 컨텐츠가 제대로 들어왔는지 확인
                if buffer_size < pivot + 9 + length:
                    break

               # 컨텐츠 추출
                content = data[pivot+9:pivot+9+length]

                if encode_type == 1:
                    try:
                        content = brotli.decompress(content)                
                    except brotli.error as e:
                        print(f"Brotli decompression error: {e}")
                        pass
  
                if data_type in parse_dict:
                    parse_func = parse_dict[data_type]
                    content = parse_func(content)
                    res.append(content)

                pivot += 9 + length

        return (res, pivot)
    
    async def _process(self, websocket) -> None:
        while True:
            try:
                pkt: Packet = await self.queue.get()
            except asyncio.CancelledError as e:
                print(f"Packet processing cancelled: {e}")
                break

            if pkt.haslayer(Raw):
                seq = pkt[TCP].seq
                payload = bytes(pkt[Raw].load)
                
                if self.current_seq is None:
                    self.current_seq = seq

                if abs(seq_distance(seq,self.current_seq)) > 10000:
                    print(f"Resetting due to large sequence gap: {seq} (current: {self.current_seq})")
                    self.tcp_segments.clear()
                    self.current_seq = None
                    self.buffer = b''
                    continue
                    
                if seq not in self.tcp_segments or self.tcp_segments[seq] != payload:
                    self.tcp_segments[seq] = payload

                if self.current_seq not in self.tcp_segments:
                    print(f"Missing segment for current sequence: {self.current_seq}, current is {seq}")

                # 재조립
                while self.current_seq in self.tcp_segments:
                    segment = self.tcp_segments.pop(self.current_seq)
                    self.buffer += segment
                    self.current_seq = (self.current_seq + len(segment)) % SEQ_MOD

                if len(self.buffer) > 1024 * 4 * 4:
                    self.buffer = self.buffer[len(self.buffer)//2:]
                    print("Buffer size exceeded, trimming to half")

                parsed, pivot = self._packet_parser(self.buffer)
                self.buffer = self.buffer[pivot:]

                if parsed:
                    try:
                        msg = json.dumps({"type": "json", "data": parsed})
                        await websocket.send(msg)
                    except Exception as e:
                        print(f"Error sending WebSocket message: {e}")
                        break

async def main() -> None:
    async def wsserve(websocket) -> None:
        streamer = PacketStreamer()
        await streamer.send_skill_mapping(websocket)
        await streamer.stream(websocket)
    async with serve(wsserve, '0.0.0.0', 8080):
        print("WebSocket server started on ws://0.0.0.0:8080")
        await asyncio.Future()  # run forever

if __name__ == '__main__':
    asyncio.run(main())