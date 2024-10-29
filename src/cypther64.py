import random

class Cypher64:
    def __init__(self):
        self.chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="

    def encode(self, data: int|str|bytes) -> str:
        types = {int: str, bytes: lambda b: b.decode('utf-8', 'ignore')}
        data = types.get(type(data), lambda x: x)(data)
        shift = random.randint(1, 63)
        buffer, coll, enc = 0, 0, [self.chars[shift]]
        for byte in map(ord, data):
            buffer = (buffer << 8) | byte
            coll += 8
            while coll >= 6:
                coll -= 6
                enc.append(self.chars[((buffer >> coll) + shift) & 0x3F])
        if coll > 0:
            enc.append(self.chars[((buffer << (6 - coll)) + shift) & 0x3F])
        return ''.join(enc)
    
    def decode(self, data: str) -> int|str:
        shift = self.chars.index(data[0])
        buffer, coll, dec = 0, 0, []
        for char in data[1:]:
            if char == '=': break
            value = (self.chars.index(char) - shift) % 64
            buffer = (buffer << 6) | value
            coll += 6
            if coll >= 8:
                coll -= 8
                dec.append((buffer >> coll) & 0xFF)
        return int(''.join(map(chr, dec))) if ''.join(map(chr, dec)).isdigit() else ''.join(map(chr, dec))