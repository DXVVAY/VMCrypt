from src import log

class VMCrypt:
    def __init__(self, memory_size: int = 4096, verbose: bool = False) -> None:
        self.regs: list = [0] * 8
        self.memory_size: int = memory_size
        self.memory: bytearray = bytearray(self.memory_size)
        self.stack: list = []
        self.ip: int = 0
        self.program: bytes = b""
        self.verbose: bool = verbose
        self.running: bool = False
        self.ops: dict = {
            0x01: self.load_imm,
            0x02: self.load_reg,
            0x03: self.load_mem,
            0x04: self.store_reg,
            0x10: self.add,
            0x11: self.sub,
            0x12: self.mul,
            0x13: self.div,
            0x14: self.mod,
            0x20: self.xor,
            0x21: self.or_op,
            0x22: self.and_op,
            0x23: self.not_op,
            0x24: self.shl,
            0x25: self.shr,
            0x26: self.rotl,
            0x27: self.rotr,
            0x30: self.jmp,
            0x31: self.jz,
            0x32: self.jnz,
            0x40: self.push,
            0x41: self.pop,
            0x50: self.sbox_sub,
            0x51: self.permute,
            0x52: self.inv_sbox,
            0x53: self.inv_permute,
            0xFF: self.halt,
        }

        self.state_history = []

    def load_program(self, program: str) -> None:
        self.program = bytes(program) if isinstance(program, list) else program

    def run(self) -> None:
        self.running = True
        while self.ip < len(self.program) and self.running:
            opcode = self.program[self.ip]
            if opcode in self.ops:
                if self.verbose:
                    log.debug(f"IP -> {self.ip} | Executing opcode -> {hex(opcode)}")
                self.ip += 1
                self.ops[opcode]()
                if self.verbose:
                    self.log_state()
                self.capture_state(opcode)
            else:
                log.failure(f"Unknown opcode -> {hex(opcode)} | IP -> {self.ip}")
                break

    def read_byte(self) -> int:
        self.ip += 1
        return self.program[self.ip - 1]

    def read_int(self) -> int:
        self.ip += 4
        return int.from_bytes(self.program[self.ip - 4:self.ip], byteorder='little')

    def load_keys(self, keys: list) -> None:
        for i in range(len(keys)):
            self.memory[i*4:(i+1)*4] = keys[i].to_bytes(4, byteorder='little')
            
    def read_reg(self) -> int:
        reg = self.read_byte()
        if reg < 0 or reg >= len(self.regs):
            log.failure(f"Invalid register -> {reg}")
            return 0
        return reg

    def reset_memory(self) -> None:
        self.regs = [0] * 8
        self.memory = bytearray(self.memory_size)
        self.stack = []
        self.ip = 0

    def sbox_sub(self) -> None:
        reg = self.read_reg()
        val = self.regs[reg]
        sbox = [0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE, 0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB]
        self.regs[reg] = sum((sbox[(val >> (i * 4)) & 0xF] << (i * 4)) for i in range(8))

    def inv_sbox(self) -> None:
        reg = self.read_reg()
        val = self.regs[reg]
        sbox = [0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE, 0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB]
        inv = [sbox.index(i) for i in range(16)]
        new_val = sum((inv[(val >> (i * 4)) & 0xF] << (i * 4)) for i in range(8))
        self.regs[reg] = new_val

    def permute(self) -> None:
        reg = self.read_reg()
        val = self.regs[reg]
        self.regs[reg] = sum(((val >> i) & 1) << [0, 2, 4, 6, 1, 3, 5, 7][i] for i in range(8))

    def inv_permute(self) -> None:
        reg = self.read_reg()
        val = self.regs[reg]
        inv = [[0, 2, 4, 6, 1, 3, 5, 7].index(i) for i in range(8)]
        self.regs[reg] = sum(((val >> i) & 1) << inv[i] for i in range(8))

    def load_imm(self) -> None:
        reg = self.read_reg()
        imm = self.read_int()
        self.regs[reg] = imm

    def load_reg(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        self.regs[reg] = self.regs[src]

    def load_mem(self) -> None:
        addr = self.read_int()
        reg = self.read_reg()
        val = self.memory[addr:addr+4]
        self.regs[reg] = int.from_bytes(val, byteorder='little')

    def store_reg(self) -> None:
        reg = self.read_reg()
        addr = self.read_int()
        val = self.regs[reg].to_bytes(4, byteorder='little')
        self.memory[addr:addr+4] = val

    def add(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        self.regs[reg] = (self.regs[reg] + self.regs[src]) & 0xFFFFFFFF

    def sub(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        self.regs[reg] = (self.regs[reg] - self.regs[src]) & 0xFFFFFFFF

    def mul(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        self.regs[reg] = (self.regs[reg] * self.regs[src]) & 0xFFFFFFFF

    def div(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        if self.regs[src] == 0: log.failure("Division by zero")
        self.regs[reg] = (self.regs[reg] // self.regs[src]) & 0xFFFFFFFF

    def mod(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        if self.regs[src] == 0: log.failure("Modulo by zero")
        self.regs[reg] = (self.regs[reg] % self.regs[src]) & 0xFFFFFFFF

    def xor(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        self.regs[reg] ^= self.regs[src]

    def or_op(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        self.regs[reg] |= self.regs[src]

    def and_op(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        self.regs[reg] &= self.regs[src]

    def not_op(self) -> None:
        reg = self.read_reg()
        self.regs[reg] = ~self.regs[reg] & 0xFFFFFFFF

    def shl(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        shift = self.regs[src] % 32
        self.regs[reg] = (self.regs[reg] << shift) & 0xFFFFFFFF

    def shr(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        shift = self.regs[src] % 32
        self.regs[reg] = (self.regs[reg] >> shift) & 0xFFFFFFFF

    def rotl(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        shift = self.regs[src] % 32
        val = self.regs[reg]
        self.regs[reg] = ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF

    def rotr(self) -> None:
        reg = self.read_reg()
        src = self.read_reg()
        shift = self.regs[src] % 32
        val = self.regs[reg]
        self.regs[reg] = ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF

    def jmp(self) -> None:
        addr = self.read_int()
        self.ip = addr

    def jz(self) -> None:
        reg = self.read_reg()
        addr = self.read_int()
        if self.regs[reg] == 0:
            self.ip = addr

    def jnz(self) -> None:
        reg = self.read_reg()
        addr = self.read_int()
        if self.regs[reg] != 0:
            self.ip = addr

    def push(self) -> None:
        reg = self.read_reg()
        self.stack.append(self.regs[reg])

    def pop(self) -> None:
        if not self.stack: log.failure("Stack underflow")
        reg = self.read_reg()
        self.regs[reg] = self.stack.pop()

    def halt(self) -> None:
        self.running = False

    def capture_state(self, opcode: int) -> None:
        self.state_history.append({
            "opcode": opcode,
            "ip": self.ip,
            "regs": list(self.regs),
            "memory": bytes(self.memory),
            "stack": list(self.stack)
        })

    def dump_process(self, filename: str) -> None:
        with open(filename, "w") as f:
            for i, state in enumerate(self.state_history):
                f.write(f"--- State {i + 1} ---\n")
                f.write(f"Opcode: {hex(state['opcode'])}\n")
                f.write(f"IP: {state['ip']}\n")
                f.write("Registers: " + " ".join(f"R{i}: {state['regs'][i]}" for i in range(len(state['regs']))) + "\n")
                memory = " ".join(f"{byte:02x}" for byte in state["memory"][:32])
                f.write(f"Memory: {memory}\n")
                f.write(f"Stack: {state['stack']}\n")
                f.write("\n")
            
    def log_state(self) -> None:
        log.debug(f"IP -> {self.ip} | regs -> {self.regs} | Stack -> {self.stack} | Memory -> {self.memory[:15]}...")