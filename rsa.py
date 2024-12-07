from typing import Tuple, Optional
from random import randint
import sys

# Problem with RSA encryption is that it is limitted in size, it means it can encrypt data which are smaller than n
# That's why in practice the RSA is ussually used to send a key for symetric encryption, and the data is encrypted using a block cypher. 

# TODO: Generate correct size private key (1024 bits)
# TODO: Automatic prime number generation 

p = 0xeb628434bcc2b89bafb2fe3e64a932dc8be90c11e954589c1120c938882ee8bba786be21787305a9bcb63c9f7ac3c2838f0c8458acfc2b62e7cbf8c1598a6d8c0d9e343662e37e37aefbe49b3fce5caafb36f03aa154fd996f15d6cec4e8f8f163182ff7c533eb40140e36861cf38e592e45127e3e02a284fcf956b0d84efc6d000ecd9b6d089f122a84725478e2cf86fce5170960c9ce838a2d71703e4ba6bcdf4e303fff1fb1e8236e02484e87f1da1857a8dabdeb5eb045673b1a06c1ff08c5c21271a432c35c6c9b38137102d9929311903afbd1ae0573e72b4b381eb6bd154236073eaa422bc98be4f141bb722a51b68a287a896bf53a79c43646842eff
q = 0xceb052c9732614fee3c0a197a5ae0fcd83422243918ab83bc678656ae0344232a7c1070b7d5aabaae2bda96bf590da4830238b606f24b29626f1bfa00cce39f5f9bb9c1c3ead98f2055e373abf01e1fe1c816e12e0ed13791461c435123dad8cbe80e474f753aa9d115a8b93c167adceaee5a18ceedef88d307427fc495d9e44d4268ba83c4a65c4667b7df79f342639da3ddd2777926848855ca0068668efe7f27d65f455074c960bbc168bfb3a1225cd6f42585ddba6b3484f36707524133b81dd01d062591fec1b756766aeebe667bf9e2480eebb5964bc5eaff4b165e142772ce64b229a7258667a3964f08e06dfbfe3e3c1cf918395b89c1fdb18907711

def RSA_keys():
    n = p * q 
    phi_n = (p - 1) * (q - 1)

    while True:
        # PRobably not save
        e = randint(1, phi_n - 1)
        # d is inverse of e because we know gdc is equal to 1 that means that 
        # S * phi_n + d * e = 1
        # d * e = 1 mod phi_n
        gcd, _, d = eea(phi_n, e)
        # d must be greater than 0, because the eea doesn't handle well negative exponents
        if gcd == 1 and d > 0:
            break
    K_pub = n, e
    K_private = n, d 
    return K_private, K_pub


def encode(text: str, K_pub: Tuple[int, int]) -> int: 
    """Encodes the text using the public key. Public key is in format [n, e]"""
    integer = text_to_int(text)
    n, e = K_pub
    encoded = exp(integer, e, n)
    return encoded


def decode(encoded: int, K_pr: Tuple[int, int]) -> str:
    """Decodes the text using the private key. Private key is in format [n, d]"""
    n, d = K_pr
    decoded = exp(encoded, d, n)
    return int_to_text(decoded)


def exp(num: int, exp: int, mod: Optional[int] = None) -> int: 
    """Implementation of fast exponentiation for fast RSA encoding and decoding. Watch out! This doesn't handle well negative exponents!"""

    if (exp == 0):
        return 0
    elif (exp == 1):
        return num
    else:
        temp = num
        # Say I want to do x^26
        # 26 is 11010
        # I drop the msb because it is always 1 (that's why it's -2, -1 because indexing from 0 and other cuz of the msb)
        for bit in bits(exp)[1:]:
            # Digits are 1, 0, 1, 0 respectively
            # We always have to square as squaring is basically multiplying the exponent by 2
            # which in binary shifts the number (pads 0 to the end) like 110 -> 1100
            temp *= temp
            if mod is not None:
                temp %= mod

            if bit:
                # If digit is 1 it means we need to correct by multiplying the temp. result
                temp *= num
                if mod is not None:
                    temp %= mod
        return temp


def bits(num: int) -> list[bool]:
    """Returns list that contains all the bits that represent the num. First is the most significant bit, and the last is the least significant bit"""
    reversed_out = []
    while num:
        reversed_out.append((num & 1) == 1)
        num >>= 1
    return list(reversed(reversed_out))
    

def eea(a: int, b: int, S_i: int = 0, S_i_min: int = 1, T_i: int = 1, T_i_min: int = 0) -> Tuple[int, int, int]: 
    """
    Extended euclidean algorithm. Returns the greatest common divisor d, such as d = S * a + T * b in format [d, S, T].
    Abd r_i = S_i * r_0 + T_i * r_1
    """
    if (a < b):
        return eea(a = b, b = a, S_i = S_i_min, S_i_min = S_i, T_i = T_i_min, T_i_min = T_i)
    
    if (b == 0):
        return a
    
    r_i = b
    r_i_min = a
    # r_i_min = q_i * r_i + r_i_plus
    r_i_plus = r_i_min % r_i
    q_i = (r_i_min - r_i_plus) // r_i

    # Because r_i_plus = r_i_min - g_i * r_i
    # And r_i_min = S_i_min * r_0 + T_i_min * r_1
    # And r_i = S_i * r_0 + T_i * r_1
    S_i_plus = S_i_min - q_i * S_i
    T_i_plus = T_i_min - q_i * T_i

    if (r_i_plus == 0):
        return r_i, int(S_i), int(T_i)
    else:
        return eea(r_i, r_i_plus, S_i = S_i_plus, S_i_min = S_i, T_i = T_i_plus, T_i_min = T_i)
    

def text_to_int(text: str) -> int: 
    binary_representation = ''.join(format(ord(ch), "08b") for ch in text)
    return int(binary_representation, 2)


def int_to_text(binary_integer: int) -> str:
    # Convert the integer to a binary string (remove the '0b' prefix)
    binary_representation = format(binary_integer, 'b')
    
    # Pad the binary string to make its length a multiple of 8
    binary_representation = binary_representation.zfill((len(binary_representation) + 7) // 8 * 8)
    
    # Split the binary string into 8-bit chunks and convert each to a character
    chars = [chr(int(binary_representation[i:i+8], 2)) for i in range(0, len(binary_representation), 8)]
    
    # Join the characters into a string
    return ''.join(chars)


if (__name__ == "__main__"):
    # Needed because of eea
    sys.setrecursionlimit(10 ** 6)
    K_pr, K_pub = RSA_keys()
    
    args = sys.argv
    data = args[1] if 1 < len(args) else "Hello world"
    print(f"data: {data}")
    encoded = encode(data, K_pub)
    print(f"encoded: {int_to_text(encoded)}")
    decoded = decode(encoded, K_pr)
    print(f"decoded: {decoded}")
