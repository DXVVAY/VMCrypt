from src import Cypher64

class Decryptor:
    def __init__(self, key: list):
        self.cypther64 = Cypher64()
        self.key = key
        self.data = None

    def decrypt(self, data: str) -> bytes:
        decrypted = bytearray()
        rounds, data = data.split(":")
        rounds = self.cypther64.decode(rounds)
        iter = 4 if rounds > 300 else 3 if rounds > 100 else 2 if rounds > 50 else 1
        data = self.cypther64.decode(data)
        for _ in range(iter):
            data = bytes.fromhex(data).decode()
            data = self.cypther64.decode(data)
            data = self.cypther64.decode(data)
        data = bytes.fromhex(data)

        keys = [[(b ^ (i + 1)) & 0xFF for b in (bytes(self.key)[1:] + bytes(self.key)[:1])[:4]] for i in range(int(rounds))]

        for idx in range(len(data) // 16):
            block = [int.from_bytes(data[idx * 16 + i * 4:idx * 16 + i * 4 + 4], byteorder='little') & 0xFFFFFFFF for i in range(4)]

            for i in reversed(range(int(rounds))):
                perm = {v: i for i, v in enumerate([0, 2, 4, 6, 1, 3, 5, 7])}
                block[:] = [sum(((block[i] >> bit) & 1) << perm[bit] for bit in range(8)) & 0xFF for i in range(4)]
                sbox = {v: k for k, v in enumerate([0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE, 0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB])}
                block = [(sum((sbox[(b >> (n * 4)) & 0xF] << (n * 4)) for n in range(2)) & 0xFF) ^ k for b, k in zip(block, keys[i])]

            decrypted.extend(block[i].to_bytes(1, byteorder='little')[0] for i in range(4))

        return bytes(decrypted[:-padding]) if 1 <= (padding := decrypted[-1]) <= 4 else bytes(decrypted)