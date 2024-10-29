from src import log, VMCrypt
import re

# just a example use of the VM
class calc:
    def __init__(self) -> None:
        self.vm = VMCrypt(verbose=True)
        self.vm.reset_memory()

    def run(self) -> None:
        log.info("Simple calculator using a custom VM")
        log.info("Supported operations -> +, -, *, /")
        while True:
            user_input = log.input(">>>")
            try:
                first, operator, second = self.parse_input(user_input)
                log.success(f"Result -> {self.calculate(first, operator, second)}")
            except Exception as e:
                log.failure(e)

    def parse_input(self, expression: str) -> tuple:
        match = re.match(r'(-?\d+)\s*([\+\-\*/])\s*(-?\d+)', expression)
        if not match: raise ValueError("Invalid expression format")
        first, operator, second = match.groups()
        return int(first), operator, int(second)

    def calculate(self, first: int, operator: str, second: int) -> int:
        program = self.generate_program(first, operator, second)
        self.vm.reset_memory()
        self.vm.load_program(program)
        self.vm.run()
        return self.vm.regs[2]

    def generate_program(self, first: int, operator: str, second: int) -> bytearray:
        program = bytearray()
        LOAD_IMM, ADD, SUB, MUL, DIV, HALT, LOAD_REG = 0x01, 0x10, 0x11, 0x12, 0x13, 0xFF, 0x02
        program += bytes([LOAD_IMM, 0x00]) + first.to_bytes(4, 'little', signed=True)
        program += bytes([LOAD_IMM, 0x01]) + second.to_bytes(4, 'little', signed=True)
        program += bytes([LOAD_IMM, 0x02]) + (0).to_bytes(4, 'little', signed=True)
        
        ops = {
            '+': bytes([ADD, 0x02, 0x00]) + bytes([ADD, 0x02, 0x01]),
            '-': bytes([LOAD_REG, 0x02, 0x00]) + bytes([SUB, 0x02, 0x01]),
            '*': bytes([MUL, 0x02, 0x00, 0x01]),
            '/': bytes([LOAD_REG, 0x02, 0x00]) + bytes([DIV, 0x02, 0x01])
        }
        
        program += ops.get(operator, bytearray())
        program += bytes([HALT])
        return program

calc().run()