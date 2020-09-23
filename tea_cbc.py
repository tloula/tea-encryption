# ********************************************* #
# Tiny Encryption Algorithm CBC Implementation  #
# Ian Bolin & Trevor Loula                      #
# CS-3350 Foundations of Computer Security      #
# ********************************************* #

import sys
import tea_algorithm

class TEA_CBC(tea_algorithm.TEA):
    #bytestrings must be padded to a length of x*8 bytes (64 bits) to align with block length.
    #this is to allow for different padding schemes

    #input: bytestring, int[4], int[2]
    @staticmethod
    def encrypt(plaintext, key, iv):
        key = [int.from_bytes(key[0], "big"), int.from_bytes(key[1], "big"), int.from_bytes(key[2], "big"), int.from_bytes(key[3], "big")]
        iv = [int.from_bytes(iv[0], "big"), int.from_bytes(iv[1], "big")]
        if len(plaintext) % 8 != 0:
            print("Bad plaintext length")
            return b""
        ciphertext = b""
        for i in range(0, len(plaintext), 8):
            temp = [int.from_bytes(plaintext[i:i+4], "big") ^ iv[0], int.from_bytes(plaintext[i+4:i+8], "big") ^ iv[1]]
            (ivLeft, ivRight) = tea_algorithm.TEA.encrypt(temp, key)
            ciphertext += ivLeft.to_bytes(4, "big")
            ciphertext += ivRight.to_bytes(4, "big")
            iv = [ivLeft, ivRight]
        return ciphertext

    #input: bytestring, int[4], int[2]
    @staticmethod
    def decrypt(ciphertext, key, iv):
        key = [int.from_bytes(key[0], "big"), int.from_bytes(key[1], "big"), int.from_bytes(key[2], "big"), int.from_bytes(key[3], "big")]
        iv = [int.from_bytes(iv[0], "big"), int.from_bytes(iv[1], "big")]
        if len(ciphertext) % 8 != 0:
            print("Bad ciphertext length")
            return b""
        plaintext = b""
        for i in range(0, len(ciphertext), 8):
            temp = [int.from_bytes(ciphertext[i:i+4], "big"), int.from_bytes(ciphertext[i+4:i+8], "big")]
            (Ltemp, Rtemp) = tea_algorithm.TEA.decrypt(temp, key)
            plaintext += (Ltemp ^ iv[0]).to_bytes(4, "big")
            plaintext += (Rtemp ^ iv[1]).to_bytes(4, "big")
            iv = temp
        return plaintext
