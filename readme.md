# VMCrypt - Python Virtual Machine
![VMCrypt](https://dexv.site/content/cdn/PwGrCQjfuYmn.png)

This project is a Python based virtual machine that can encrypt and decrypt strings. It includes a custom virtual machine (`VMCrypt`) and uses it for secure data encryption and decryption.

## Key Features

- **Virtual Machine (VMCrypt)**: A simple program that can perform various operations like addition, subtraction, and logic tasks.
- **Encryption & Decryption**: Uses the virtual machine to scramble and unscramble messages.
- **Detailed Logging**: Option to print out detailed messages about what the virtual machine is doing.
- **Custom Keys**: You can use your own keys to encrypt and decrypt messages.

## How It Works

### 1. VMCrypt

`VMCrypt` is the core part of this project. It can do operations like:

- **Math**: Adding, subtracting, multiplying, and dividing.
- **Logic**: Bitwise operations like AND, OR, and XOR.
- **Memory**: Load and store data in registers and memory.
- **Jumping**: Move to different parts of the program.
- **Cryptography**: Use S-box (substitution) and permutation for encryption.

### 2. Encryptor

The `Encryptor` class creates a program for the virtual machine to run, which encrypts your data using bitwise operations and custom keys.

### 3. Decryptor

The `Decryptor` class does the opposite, it takes encrypted data and converts it back to the original message.

### 4. Client

`Client` is a simple way to use the `Encryptor` and `Decryptor`. It combines everything into one easy to use interface.

## Encryption Algorithm

### 1. Key Expansion

The `update_data` method generates keys for each round by transforming each byte in the original key. This adds complexity by creating a unique set of keys for each round.

```python
def update_data(self, data: str) -> None:
    # generate keys for each round by xor'ing and shifting
    self.keys = [[(b ^ (i + 1)) & 0xFF for b in (bytes(self.key)[1:] + bytes(self.key)[:1])[:4]] 
                 for i in range(self.rounds)]
```

For example, if `key = [1, 2, 3, 4]` and `rounds = 3`, this would create three unique key sets, each transformed for added security.

### 2. Data Preparation

The data is converted to bytes and padded to ensure it’s divisible by 4 (since the encryption operates on 4 byte blocks).

```python
self.data = bytes(data, "utf-8")
self.data += bytes([(4 - len(data) % 4) or 4] * ((4 - len(data) % 4) or 4))
```

For instance, if `data = "dexv"`, the byte format would be padded to `b'dexv\x03\x03\x03'` (adding three `0x03` bytes to make the length a multiple of 4).

### 3. VM Program Generation

The `vm_program` method creates instructions to process each 4 byte block of data with the VM. It sets up operations like loading values, applying xor, and shifting.

```python
def vm_program(self, message: bytes, keys: list, program: list = []) -> bytes:
    for idx in range(len(message) // 4):
        block = message[idx * 4: (idx + 1) * 4]
        # push the message to the stack for analysis pourposes
        for i in range(4): program.extend([[0x01, i, *self.to_bytes(block[i])], [0x40, i]])
        
        # apply each round of key transformations
        for key in keys:
            program.extend([0x01, 4 + i, *self.to_bytes(key[i])] for i in range(4))
            program.extend([0x20, i, 4 + i] for i in range(4))  # xor with key
            program.extend([0x50, i] for i in range(4))         # accumulate values
            program.extend([0x51, i] for i in range(4))         # apply bit shift
    program.append([0xFF])  # end of program
    return bytes([item for sublist in program for item in sublist])
```

For each 4 byte block, the program adds instructions to transform the bytes using the keys generated in step 1.

### 4. Running the VM

With `update_data` finished, the program is loaded into the VM. When `encrypt` is called, the VM executes the program, transforming the data.

```python
def encrypt(self) -> str:
    self.vm.run()
    encrypted = bytearray()

    # gather transformed data from the VM’s memory
    for idx in range(len(self.data) // 4):
        for i in range(4):
            start = idx * 16 + i * 4
            end = start + 4
            chunk = self.vm.memory[start:end]
            encrypted.extend(chunk)
```

This retrieves the encrypted data from `vm.memory`, where each block has been modified by the loaded program.

### 5. Final Encoding

The transformed data is encoded into a hexadecimal format and then encoded using `Cypher64 (custom b64?)` multiple times to strengthen the encryption.

```python
rounds = self.cypther64.encode(self.rounds)
iter = 4 if self.rounds > 300 else 3 if self.rounds > 100 else 2 if self.rounds > 50 else 1
encrypted = self.cypther64.encode(bytes(encrypted).hex())
for _ in range(iter):
    encrypted = self.cypther64.encode(encrypted)
    encrypted = bytes(encrypted.encode()).hex()
    encrypted = self.cypther64.encode(encrypted)

return f"{rounds}:{encrypted}"
```

For instance, if `rounds = 3` and the transformed data is `b'\x12\x34\x56\x78'`, the encoding may convert it to a secure, encoded string like `5fP:QW5mYlNmZk5v`.

## How to Use

### Requirements

- Python 3.8 or higher.
- Install any required packages.

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/DXVVAY/VMCrypt.git
   cd VMCrypt
   ```

2. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

### Example

Here's how you can encrypt and decrypt a message:

```python
from main import Client

# Define a 32-byte key (example)
key = [125, 161, 25, 137, 238, 90, 199, 2, 140, 135, 60, 50, 95, 117, 38, 63, 204, 90, 202, 134, 112, 217, 145, 34, 220, 59, 121, 161, 184, 89, 244, 164]

# Create a Client instance with the key
client = Client(key=key, verbose=False, difficulty=15)

# Define the data to encrypt
data = "Dexv sexy frfr!"

# Encrypt the data
encrypted = client.encrypt(data)
print(f"Encrypted: {encrypted}")

# Decrypt the data
decrypted = client.decrypt(encrypted)
print(f"Decrypted: {decrypted}")
```

### Detailed Logging

To see what the virtual machine is doing during encryption, set `verbose=True`:

```python
from src.vmcrypt import VMCrypt

vm = VMCrypt(verbose=True)
```

This will show you more information about each step the virtual machine takes.

## Project Structure

- `analyzer.py`: Analyzes the virtual machine's behavior.
- `calculator.py`: Performs calculations.
- `encryption.py`: Handles encryption logic.
- `src/vmcrypt.py`: The virtual machine.
- `src/vm_encrypt.py`: Handles encryption.
- `src/vm_decrypt.py`: Handles decryption.
- `src/logger.py`: Logging.

## How to Contribute

We welcome contributions! Here’s how:

1. Fork this project.
2. Create a new branch: `git checkout -b feature/your-feature`.
3. Make your changes and commit them: `git commit -m 'Add some feature'`.
4. Push to your branch: `git push origin feature/your-feature`.
5. Open a pull request.

# Credits

* **DEXV** - *Shit head (retarded)* - [DEXV](https://dexv.lol) - Main Author
* **DCH** - *Frenchie* - [DCH-VM](https://github.com/DCH81/Dch-VM) - Inspiration