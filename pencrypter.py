#!/usr/bin/env python3
#
# https://en.wikipedia.org/wiki/Crypt_(C)
# https://www.gnu.org/software/libc/
# https://www.gnu.org/software/libc/manual/html_node/crypt.html
# https://www.gnu.org/software/libc/manual/html_node/getpass.html
# https://www.akkadia.org/drepper/sha-crypt.html
# https://www.akkadia.org/drepper/SHA-crypt.txt
# https://docs.python.org/3/library/crypt.html
#

import getpass
import hashlib
import os
import sys

b64table = b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def sha512_crypt_core(password, salt):
    rounds = 5000

    digest_B = hashlib.sha512(password + salt + password).digest()

    digest_A = hashlib.sha512(password + salt +
        digest_B * (len(password) // 64) + digest_B[:len(password) % 64] +
        b''.join(map(
            lambda bit: digest_B if bit == '1' else password,
            reversed('{:b}'.format(len(password)))
        ))
    ).digest()

    digest_DP = hashlib.sha512(password * len(password)).digest()
    P = digest_DP * (len(password) // 64) + digest_DP[:len(password) % 64]

    digest_DS = hashlib.sha512(salt * (16 + digest_A[0])).digest()
    S = digest_DS * (len(salt) // 64) + digest_DS[:len(salt) % 64]

    # 21
    digest_C = digest_A
    for i in range(rounds):

        # 21.a
        digest_context_C = hashlib.sha512()

        # 21.b
        if i % 2 == 1:
            digest_context_C.update(P)

        # 21.c
        if i % 2 == 0:
            digest_context_C.update(digest_C)

        # 21.d
        if i % 3 != 0:
            digest_context_C.update(S)

        # 21.e
        if i % 7 != 0:
            digest_context_C.update(P)

        # 21.f
        if i % 2 == 1:
            digest_context_C.update(digest_C)

        # 21.g
        if i % 2 == 0:
            digest_context_C.update(P)

        # 21.h
        digest_C = digest_context_C.digest()

    # 22
    permutation_indices = (
        42, 21,  0,  1, 43, 22, 23,  2, 44,
        45, 24,  3,  4, 46, 25, 26,  5, 47,
        48, 27,  6,  7, 49, 28, 29,  8, 50,
        51, 30,  9, 10, 52, 31, 32, 11, 53,
        54, 33, 12, 13, 55, 34, 35, 14, 56,
        57, 36, 15, 16, 58, 37, 38, 17, 59,
        60, 39, 18, 19, 61, 40, 41, 20, 62,
        63
    )
    return myb64encode(bytes(digest_C[i] for i in permutation_indices))

def sha512_crypt(password, salt):
    assert type(password) is bytes
    assert type(salt) is bytes
    assert len(salt) <= 16
    assert all(map(lambda c: c in b64table, salt))
    checksum = sha512_crypt_core(password, salt)
    return b'$6$' + salt + b'$' + checksum

def is_valid_salt_arg(salt):
    return len(salt) <= 16 and all(map(lambda c: c in b64table, salt.encode()))

def get_salt_from_cmdline_or_urandom():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == '--salt' and is_valid_salt_arg(args[1]):
        return args[1].encode()
    if len(args) == 0:
        return myb64encode(os.urandom(12))
    print('bad cmdline arguments', file=sys.stderr)
    sys.exit(1)

def myb64encode_core(stream):
    # NOTE: crypt(3) uses little-endian ordering
    result = ()
    for triple in zip(stream[0::3], stream[1::3], stream[2::3]):
        value = triple[0] | (triple[1] << 8) | (triple[2] << 16)
        quadruple = (
            (value >>  0) & 0b111111,
            (value >>  6) & 0b111111,
            (value >> 12) & 0b111111,
            (value >> 18) & 0b111111
        )
        result += quadruple
    return result

def myb64encode(stream):
    stream_len = len(stream)
    if stream_len % 3 != 0:
        stream += b'\x00' * (3 - stream_len % 3)
    result = myb64encode_core(stream)
    if stream_len % 3 != 0:
        result = result[:stream_len % 3 - 3]
    return bytes(map(lambda u: b64table[u], result))

def main():
    salt = get_salt_from_cmdline_or_urandom()
    password = getpass.getpass().encode()
    sha512_crypt_result = sha512_crypt(password, salt)
    print(sha512_crypt_result.decode())

if __name__ == '__main__':
    main()
