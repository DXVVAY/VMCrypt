from src import Cypher64
from src import vmcrypt

class Encryptor:
    def __init__(self, key: list, vm: vmcrypt.VMCrypt, rounds: int) -> None:
        self.cypther64 = Cypher64()
        self.rounds = rounds
        self.key = key
        self.vm = vm

    def update_data(self, data: str) -> None:
        self.keys = [[(b ^ (i + 1)) & 0xFF for b in (bytes(self.key)[1:] + bytes(self.key)[:1])[:4]] for i in range(self.rounds)]
        self.data = bytes(data, "utf-8")
        self.data += bytes([(4 - len(data) % 4) or 4] * ((4 - len(data) % 4) or 4))
        self.program = self.vm_program(self.data, self.keys)
        self.vm.load_program(self.program)

    def to_bytes(self, n: int) -> list:
        return [(n >> (i * 8)) & 0xFF for i in range(4)]

    def vm_program(self, message: bytes, keys: list, program: list = []) -> bytes:
        for idx in range(len(message) // 4):
            block = message[idx * 4: (idx + 1) * 4]
            for i in range(4): program.extend([[0x01, i, *self.to_bytes(block[i])], [0x40, i]])

        for idx in range(len(message) // 4):
            block = message[idx * 4: (idx + 1) * 4]
            program.extend([0x01, i, *self.to_bytes(block[i])] for i in range(4))
            for key in keys:
                program.extend([0x01, 4 + i, *self.to_bytes(key[i])] for i in range(4))
                program.extend([0x20, i, 4 + i] for i in range(4))
                program.extend([0x50, i] for i in range(4))
                program.extend([0x51, i] for i in range(4))
            program.extend([0x04, i, *self.to_bytes(idx * 16 + i * 4)] for i in range(4))
        program.append([0xFF])
        return bytes([item for sublist in program for item in sublist])
    
    def encrypt(self) -> str:
        self.vm.run()
        encrypted = bytearray()
    
        for idx in range(len(self.data) // 4):
            for i in range(4):
                start = idx * 16 + i * 4
                end = start + 4
                chunk = self.vm.memory[start:end]
                encrypted.extend(chunk)
    
        self.vm.reset_memory()
        rounds = self.cypther64.encode(self.rounds)
        iter = 4 if self.rounds > 300 else 3 if self.rounds > 100 else 2 if self.rounds > 50 else 1
        encrypted = self.cypther64.encode(bytes(encrypted).hex())
        for _ in range(iter):
            encrypted = self.cypther64.encode(encrypted)
            encrypted = bytes(encrypted.encode()).hex()
            encrypted = self.cypther64.encode(encrypted)
    
        return f"{rounds}:{encrypted}"