# Cryptocore

# CryptoCore

CryptoCore is a command-line tool for encrypting and decrypting files using AES-128 in ECB mode.

## Features

- AES-128 encryption and decryption
- ECB mode of operation
- PKCS#7 padding
- Hexadecimal encryption key
- Binary file support
- Input validation and error handling

## Requirements

- Python 3.10 or newer
- pycryptodome

## Installation

Clone the repository:

```bash
git clone https://github.com/denisssmile/Cryptocore.git
cd Cryptocore
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Encryption:

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Decryption:

```bash
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

## Testing

The project will include tests for encryption, decryption, padding validation, and file handling.
