# ********************************************* #
# Tiny Encryption Algorithm CBC Implementation  #
# Ian Bolin & Trevor Loula                      #
# CS-3350 Foundations of Computer Security      #
# ********************************************* #

import sys
import tea_algorithm

class TEA_ECB(tea_algorithm.TEA):
    #bytestrings must be padded to a length of x*8 bytes (64 bits) to align with block length.
    #this is to allow for different padding schemes

    #input: bytestring, int[4], int[2]
    @staticmethod
    def encrypt(plaintext, key):
        key = [int(key[0]), int(key[1]), int(key[2]), int(key[3])]
        if len(plaintext) % 8 != 0:
            print("Bad plaintext length")
            return b""
        ciphertext = b""
        for i in range(0, len(plaintext), 8):
            temp = [int.from_bytes(plaintext[i:i+4], "big"), int.from_bytes(plaintext[i+4:i+8], "big")]
            (Left, Right) = tea_algorithm.TEA.encrypt(temp, key)
            ciphertext += Left.to_bytes(4, "big")
            ciphertext += Right.to_bytes(4, "big")
        return ciphertext

    #input: bytestring, int[4], int[2]
    @staticmethod
    def decrypt(ciphertext, key):
        key = [int(key[0]), int(key[1]), int(key[2]), int(key[3])]
        if len(ciphertext) % 8 != 0:
            print("Bad ciphertext length")
            return b""
        plaintext = b""
        for i in range(0, len(ciphertext), 8):
            temp = [int.from_bytes(ciphertext[i:i+4], "big"), int.from_bytes(ciphertext[i+4:i+8], "big")]
            (Ltemp, Rtemp) = tea_algorithm.TEA.decrypt(temp, key)
            plaintext += Ltemp.to_bytes(4, "big")
            plaintext += Rtemp.to_bytes(4, "big")
        return plaintext