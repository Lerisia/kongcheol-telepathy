import struct
from functools import lru_cache
from dataclasses import dataclass
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

HEAD_SIGNATURE = b'\x65\x27' + b'\x00' * 7   # 9-byte packet prefix
TAIL_SIGNATURE = b'\xe0\x27' + b'\x00' * 7
SIG_LEN   = len(HEAD_SIGNATURE)              # 9
TLV_HDR   = struct.Struct('<IIB')       # type(4) len(4) enc(1). Total 9 bytes
TLV_HDR_LEN = TLV_HDR.size              # 9

@lru_cache(maxsize=256)
def extract_flags(flags: bytes) -> dict:
    result = {}
    for index, name, mask in FLAG_BITS:
        result[name] = int((flags[index] & mask) != 0) if index < len(flags) else 0
    return result

@dataclass
class TLVHeader:
    data_type: int
    length: int
    encode_type: int

class PacketParser:
    def __init__(self):
        self._parse_dict = {
            10299: self._parse_damage,
            100041: self._parse_action,
            100178: self._parse_hp_changed,
            10701: self._parse_self_damage,
        }
        
    def packet_parser(self, data: bytes) -> tuple[list,int]:
        result = []
        pivot = 0
        buffer_size = len(data)

        while(pivot < len(data)):
            pivot = self._find_packet_head(data, pivot)
            if pivot == -1:
                break
            
            if self._find_packet_tail(data, pivot) == -1:
                break
            
            pivot += TLV_HDR_LEN
            
            while ( buffer_size > pivot + TLV_HDR_LEN):
                header = self._process_header(data, pivot, buffer_size)
                if header is None:
                    break
                
                content = self._process_record(data, pivot, header)
                if content is not None:
                    result.append(content)
                pivot += TLV_HDR_LEN + header.length

        return (result, pivot)
    
    def _parse_damage(self, data):
        if len(data) != 35:
            print("Damage data size mismatch with expected.")
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

    def _parse_action(self, data):
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

    def _parse_hp_changed(self, data):
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

    def _parse_self_damage(self, data):
        if len(data) != 53:
            print("Damage data size mismatch with expected.")
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
    
    def _find_packet_head(self, data, pivot):
        return data.find(HEAD_SIGNATURE, pivot)

    def _find_packet_tail(self, data, pivot):
        return data.find(TAIL_SIGNATURE, pivot + SIG_LEN)
    
    def _process_header(self, data, pivot, buffer_size):
        data_type = int.from_bytes(data[pivot:pivot+4], byteorder='little')
        length = int.from_bytes(data[pivot+4:pivot+8], byteorder='little')
        encode_type = data[pivot+8]
        
        if data_type == 0:
            return None

        if pivot + TLV_HDR_LEN + length > buffer_size:
            return None
        
        return TLVHeader(data_type=data_type, length=length, encode_type=encode_type) 
    
    def _process_record(self, data, pivot, header):
        content = data[pivot + TLV_HDR_LEN:pivot + TLV_HDR_LEN + header.length]

        if header.encode_type == 1:
            try:
                content = brotli.decompress(content)                
            except brotli.error as e:
                print(f"Brotli decompression error: {e}")
                pass

        if header.data_type in self._parse_dict:
            parse_func = self._parse_dict[header.data_type]
            return parse_func(content)
        
        return None