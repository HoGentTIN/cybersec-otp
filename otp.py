#!/usr/bin/env python3

import argparse
import sys
import tabulate


LOWERCASE_CHAR = "abcdefghijklmnopqrstuvwxyz"

ROT13_SHIFT = 13


def is_word_valid(word):
    for c in word:
        if not is_char_valid(c):
            return False

    return True


def is_char_valid(c):
    return c in LOWERCASE_CHAR


def char_to_int(c):
    return LOWERCASE_CHAR.find(c)


def int_to_char(i):
    return LOWERCASE_CHAR[i]


def get_chars(word):
    return [c for c in word]


def get_ints(word):
    return [char_to_int(c) for c in word]


def generate_rot13_key(word):
    return ["n" for _ in word]


def encrypt(plaintext, key):
    plaintext_chars = get_chars(plaintext)
    plaintext_ints = get_ints(plaintext)

    key_chars = get_chars(key)
    key_ints = get_ints(key)

    ciphertext_ints_nomod = []
    ciphertext_ints = []
    ciphertext_chars = []
    for i in range(len(plaintext_chars)):
        ciphertext_ints_nomod.append(plaintext_ints[i] + key_ints[i])
        ciphertext_ints.append(ciphertext_ints_nomod[i] % 26)
        ciphertext_chars.append(int_to_char(ciphertext_ints[i]))

    print(
        tabulate.tabulate(
            [
                ["plaintext"] + plaintext_chars,
                ["plaintext"] + plaintext_ints,
                [],
                ["key"] + key_chars,
                ["key"] + key_ints,
                [],
                ["plaintext + key"] + ciphertext_ints_nomod,
                ["(plaintext + key) mod 26"] + ciphertext_ints,
                ["ciphertext"] + ciphertext_chars,
            ],
            tablefmt="simple_grid",
        )
    )


def decrypt(ciphertext, key):
    ciphertext_chars = get_chars(ciphertext)
    ciphertext_ints = get_ints(ciphertext)

    key_chars = get_chars(key)
    key_ints = get_ints(key)

    plaintext_ints_nomod = []
    plaintext_ints = []
    plaintext_chars = []
    for i in range(len(ciphertext_chars)):
        plaintext_ints_nomod.append(ciphertext_ints[i] - key_ints[i])
        plaintext_ints.append(plaintext_ints_nomod[i] % 26)
        plaintext_chars.append(int_to_char(plaintext_ints[i]))

    print(
        tabulate.tabulate(
            [
                ["ciphertext"] + ciphertext_chars,
                ["ciphertext"] + ciphertext_ints,
                [],
                ["key"] + key_chars,
                ["key"] + key_ints,
                [],
                ["ciphertext - key"] + plaintext_ints_nomod,
                ["(ciphertext - key) mod 26"] + plaintext_ints,
                ["plaintext"] + plaintext_chars,
            ],
            tablefmt="simple_grid",
        )
    )


parser = argparse.ArgumentParser(
    prog="otp",
    description="One Time Pad",
    epilog="(c) Martijn Saelens",
)


encrypt_or_decrypt = parser.add_mutually_exclusive_group(required=True)
encrypt_or_decrypt.add_argument("-e", "--encrypt", metavar="PLAINTEXT")
encrypt_or_decrypt.add_argument("-d", "--decrypt", metavar="CIPHERTEXT")

parser.add_argument("-k", "--key", metavar="KEY")

args = parser.parse_args()


if args.encrypt:
    plaintext = args.encrypt

    if not is_word_valid(plaintext):
        print(
            f"ERROR: Plaintext contains invalid characters. Only characters '{LOWERCASE_CHAR}'' are allowed"
        )
        sys.exit(1)

    key = ""
    if args.key:
        if not is_word_valid(args.key):
            print(
                f"ERROR: Key contains invalid characters. Only '{LOWERCASE_CHAR}' are allowed"
            )
            sys.exit(1)

        if len(plaintext) > len(args.key):
            print(
                "ERROR: The length of the key must be equal or larger than the length of the plaintext."
            )
            sys.exit(1)

        key = args.key
    else:
        key = generate_rot13_key(plaintext)

    encrypt(plaintext, key)

elif args.decrypt:
    ciphertext = args.decrypt

    if not is_word_valid(ciphertext):
        print(
            f"ERROR: Ciphertext contains invalid characters. Only characters '{LOWERCASE_CHAR}'' are allowed"
        )
        sys.exit(1)

    key = ""
    if args.key:
        if not is_word_valid(args.key):
            print(
                f"ERROR: Key contains invalid characters. Only '{LOWERCASE_CHAR}' are allowed"
            )
            sys.exit(1)

        if len(ciphertext) > len(args.key):
            print(
                "ERROR: The length of the key must be equal or larger than the length of the ciphertext."
            )
            sys.exit(1)

        key = args.key
    else:
        key = generate_rot13_key(ciphertext)

    decrypt(ciphertext, key)
