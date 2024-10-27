# Python Virtual Machine

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

## How to Use

### Requirements

- Python 3.8 or higher.
- Install any required packages.

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/DXVVAY/VMCrypt.git
   cd python-vm-encryptor
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
client = Client(key=key, verbose=False)

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
from vmcrypt import VMCrypt

vm = VMCrypt(verbose=True)
```

This will show you more information about each step the virtual machine takes.

## Project Structure

- `main.py`: Main file to use for encryption and decryption.
- `src/vmcrypt.py`: The virtual machine.
- `src/vm_encrypt.py`: Handles encryption.
- `src/vm_decrypt.py`: Handles decryption.
- `src/logger.py`: logging.

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