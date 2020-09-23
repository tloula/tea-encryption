# ********************************************* #
# Tiny Encryption Algorithm Implementation      #
# Ian Bolin & Trevor Loula                      #
# CS-3350 Foundations of Computer Security      #
# ********************************************* #

import sys
from ctypes import *
import tea_algorithm

class TEA_CBC(tea_algorithm.TEA):
    @staticmethod
    def encrypt(plaintext, key, iv):
        if len(plaintext) % 8 != 0:
            print("Bad plaintext length")
            return b""
        ciphertext = b""
        for i in range(0, len(plaintext)-8, 8):
            temp = [int.from_bytes(plaintext[i:i+4], "big") ^ iv[0], int.from_bytes(plaintext[i+4:i+8], "big") ^ iv[1]]
            (ivLeft, ivRight) = tea_algorithm.TEA.encrypt(temp, key)
            ciphertext += ivLeft.to_bytes(4, "big")
            ciphertext += ivRight.to_bytes(4, "big")
            iv = [ivLeft, ivRight]
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key, iv):
        if len(ciphertext) % 8 != 0:
            print("Bad ciphertext length")
            return b""
        plaintext = b""
        for i in range(0, len(ciphertext)-8, 8):
            temp = [int.from_bytes(ciphertext[i:i+4], "big"), int.from_bytes(ciphertext[i+4:i+8], "big")]
            (Ltemp, Rtemp) = tea_algorithm.TEA.decrypt(temp, key)
            plaintext += (Ltemp ^ iv[0]).to_bytes(4, "big")
            plaintext += (Rtemp ^ iv[1]).to_bytes(4, "big")
            iv = temp
        return plaintext
