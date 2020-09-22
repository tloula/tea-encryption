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
        ciphertext = b""
        for i in range(0, plaintext.len-4, 4):
            temp = plaintext[i:i+4] ^ iv
            iv = super.encrypt(temp, key)
            ciphertext += iv
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key, iv):
        plaintext = b""
        for i in range(0, ciphertext.len-4, 4):
            temp = ciphertext[i:i+4]
            plaintext =+ super.encrypt(temp, key) ^ iv
            iv = temp
        return plaintext
