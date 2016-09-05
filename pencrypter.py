#!/usr/bin/env python3
#
# https://en.wikipedia.org/wiki/Crypt_(C)
# https://www.gnu.org/software/libc/
# https://www.gnu.org/software/libc/manual/html_node/crypt.html
# https://www.gnu.org/software/libc/manual/html_node/getpass.html
# https://www.akkadia.org/drepper/sha-crypt.html
# https://www.akkadia.org/drepper/SHA-crypt.txt
# https://docs.python.org/3/library/crypt.html
# https://sourceware.org/git/?p=glibc.git;a=tree;f=crypt;h=f9f4798146d372f4c1cdd01605eba039a0f1e99f;hb=refs/heads/release/2.23/master

import argparse
import getpass
import hashlib
import os
import re
import sys

b64table = b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def sha512_crypt(password, salt, rounds=5000):
    assert type(password) is bytes
    assert type(salt) is bytes and len(salt) <= 16
    assert all(map(lambda c: c in b64table, salt))
    assert type(rounds) is int and 1000 <= rounds <= 999999999
    checksum = sha512_crypt_core(password, salt, rounds)
    return (
        b'$6' +
        ('$rounds={:d}'.format(rounds).encode() if rounds != 5000 else b'') +
        b'$' + salt +
        b'$' + checksum
    )

def sha512_crypt_core(password, salt, rounds):

    B = hashlib.sha512(password + salt + password).digest()

    A = hashlib.sha512(password + salt +
        B * (len(password) // 64) + B[:len(password) % 64] +
        b''.join(map(
            lambda bit: B if bit == '1' else password,
            reversed('{:b}'.format(len(password)))
        ))
    ).digest()

    DP = hashlib.sha512(password * len(password)).digest()
    P = DP * (len(password) // 64) + DP[:len(password) % 64]

    DS = hashlib.sha512(salt * (16 + A[0])).digest()
    S = DS * (len(salt) // 64) + DS[:len(salt) % 64]

    C = A
    for round_no in range(rounds):
        C_context = hashlib.sha512()
        C_context.update(P if round_no % 2 == 1 else C)
        C_context.update(S if round_no % 3 != 0 else b'')
        C_context.update(P if round_no % 7 != 0 else b'')
        C_context.update(P if round_no % 2 == 0 else C)
        C = C_context.digest()

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
    D = bytes(C[i] for i in permutation_indices)

    return myb64encode(D)



def myb64encode(stream):
    assert type(stream) is bytes
    stream_len = len(stream)
    if stream_len % 3 != 0:
        stream += b'\x00' * (3 - stream_len % 3)
    result = myb64encode_core(stream)
    if stream_len % 3 != 0:
        result = result[:stream_len % 3 - 3]
    return bytes(map(lambda u: b64table[u], result))

def myb64encode_core(stream):
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



def main():
    obj = cmdline_args_handler()
    if obj.salt is None:
        #
        # 48 random bits
        # 6 random bytes
        # 8 random base64 alphabets
        #
        obj.salt = myb64encode(os.urandom(6))
    if obj.rounds is None:
        obj.rounds = 5000
    if obj.password is None:
        obj.password = getpass.getpass().encode()
    if not all(map(lambda c: 32 <= c <= 126, obj.password)):
        print('Error: must use ASCII printable characters', file=sys.stderr)
        sys.exit(1)
    print(sha512_crypt(obj.password, obj.salt, obj.rounds).decode())

def cmdline_args_handler():
    parser = argparse.ArgumentParser(
        description='UNIX style password encryption using SHA-512')
    parser.add_argument('--salt', type=w(cmdline_args_salt),
        help='specify the salt (default: 8 random base64 alphabets)')
    parser.add_argument('--rounds', type=w(cmdline_args_rounds),
        help='specify the number of iterations (default: 5000)')
    parser.add_argument('--password', type=w(cmdline_args_password),
        help='specify the password (default: user input from prompt)')
    return parser.parse_args()

def cmdline_args_salt(string):
    assert re.fullmatch('^[./0-9A-Za-z]*$', string)

    # if there are more than 16 base64 alphabets (more than 12 bytes of info)
    # only the first 16 base64 alphabets will be kept
    string = string[:16]

    return string.encode()

def cmdline_args_rounds(string):
    _rounds = int(string)
    if _rounds < 1000:
        return 1000
    if _rounds > 999999999:
        return 999999999
    return _rounds

def cmdline_args_password(string):
    assert all(map(lambda c: 32 <= ord(c) <= 126, string))
    return string.encode()

def w(func):
    def new_func(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            pass
        raise argparse.ArgumentTypeError(*args, **kwargs)
    return new_func

if __name__ == '__main__':
    main()
