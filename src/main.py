
import argparse
import sys
from pathlib import Path

from Crypto.Cipher import AES


BLOCK_SIZE = 16


def parse_key(key_hex: str) -> bytes:
    """Проверяет и преобразует HEX-ключ AES-128 в байты."""
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise ValueError(
            "Ключ должен быть шестнадцатеричной строкой."
        ) from exc

    if len(key) != 16:
        raise ValueError(
            "Ключ AES-128 должен содержать 32 HEX-символа (16 байт)."
        )

    return key


def add_padding(data: bytes) -> bytes:
    """Добавляет дополнение PKCS#7."""
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length]) * padding_length


def remove_padding(data: bytes) -> bytes:
    """Проверяет и удаляет дополнение PKCS#7."""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Некорректный размер данных для PKCS#7.")

    padding_length = data[-1]

    if not 1 <= padding_length <= BLOCK_SIZE:
        raise ValueError("Некорректное дополнение PKCS#7.")

    expected = bytes([padding_length]) * padding_length

    if data[-padding_length:] != expected:
        raise ValueError("Проверка дополнения PKCS#7 не пройдена.")

    return data[:-padding_length]


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Шифрует данные AES-128 в режиме ECB."""
    padded = add_padding(data)
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = []

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        blocks.append(cipher.encrypt(block))

    return b"".join(blocks)


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Расшифровывает AES-128 ECB и удаляет PKCS#7."""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "Зашифрованный файл должен содержать целое "
            "число блоков по 16 байт."
        )

    cipher = AES.new(key, AES.MODE_ECB)
    blocks = []

    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE]
        blocks.append(cipher.decrypt(block))

    return remove_padding(b"".join(blocks))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Шифрование файлов с помощью AES-128 ECB.",
    )

    parser.add_argument(
        "--algorithm", required=True, choices=["aes"]
    )
    parser.add_argument(
        "--mode", required=True, choices=["ecb"]
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true")
    operation.add_argument("--decrypt", action="store_true")

    parser.add_argument("--key", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        key = parse_key(args.key)
        input_path = Path(args.input)

        if not input_path.is_file():
            raise ValueError(
                f"Входной файл не найден: {input_path}"
            )

        if args.output:
            output_path = Path(args.output)
        elif args.encrypt:
            output_path = Path(str(input_path) + ".enc")
        else:
            output_path = Path(str(input_path) + ".dec")

        if input_path.resolve() == output_path.resolve():
            raise ValueError(
                "Входной и выходной файлы должны отличаться."
            )

        data = input_path.read_bytes()

        if args.encrypt:
            result = encrypt_ecb(data, key)
        else:
            result = decrypt_ecb(data, key)

        output_path.write_bytes(result)

        action = "Зашифровано" if args.encrypt else "Расшифровано"
        print(f"{action}: {input_path} -> {output_path}")
        return 0

    except (ValueError, OSError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
