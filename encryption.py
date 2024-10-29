from src import *
import random
import time

class Client:
    def __init__(self, key: list, verbose: bool = False, difficulty: int = random.randint(1, 15)) -> None:
        self.key = key
        self.vm = vmcrypt.VMCrypt(verbose=verbose)
        self.encryptor = vm_encrypt.Encryptor(self.key, self.vm, difficulty)
        self.decryptor = vm_decrypt.Decryptor(self.key)

    def decrypt(self, data: str) -> str:
        return self.decryptor.decrypt(data).decode("utf-8")
    
    def encrypt(self, data: str) -> str:
        self.encryptor.update_data(data)
        return self.encryptor.encrypt()

inst = Client(
    key=[125, 161, 25, 137, 238, 90, 199, 2, 140, 135, 60, 50, 95, 117, 38, 63, 204, 90, 202, 134, 112, 217, 145, 34, 220, 59, 121, 161, 184, 89, 244, 164], 
    verbose=False,
    difficulty=51 # the higher the difficulty the slower (dont recommend going over 300)
)
data = "Dexv sexy frfr!"

start = time.time()
encrypted = inst.encrypt(data)
log.info(f"{encrypted}", start=start, end=time.time(), level="Encrypted", hide_chars=70)
inst.vm.dump_process("VMDump.txt")
start = time.time()
decrypted = inst.decrypt(encrypted)
log.info(decrypted, start=start, end=time.time(), level="Decrypted")