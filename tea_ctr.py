# ********************************************* #
# Tiny Encryption Algorithm CBC Implementation  #
# Ian Bolin & Trevor Loula                      #
# CS-3350 Foundations of Computer Security      #
# ********************************************* #

import sys
import tea_algorithm

class TEA_CTR(tea_algorithm.TEA):
    #bytestrings must be padded to a length of x*8 bytes (64 bits) to align with block length.
    #this is to allow for different padding schemes

    #input: bytestring, int[4], int[2]
    @staticmethod
    def encrypt(plaintext, key, iv):
        key = [int(key[0]), int(key[1]), int(key[2]), int(key[3])]
        iv = [int(iv[0]), int(iv[1])]
        if len(plaintext) % 8 != 0:
            print("Bad plaintext length")
            return b""
        ciphertext = b""
        for i in range(0, len(plaintext), 8):
            temp = [int.from_bytes(plaintext[i:i+4], "big"), int.from_bytes(plaintext[i+4:i+8], "big")]
            (Left, Right) = tea_algorithm.TEA.encrypt(iv, key)
            ciphertext += (Left ^ temp[0]).to_bytes(4, "big")
            ciphertext += (Right ^ temp[1]).to_bytes(4, "big")
            if (iv[1] == 0xffffffff):
                iv[1] = 0x0
                if (iv[0] == 0xffffffff):
                    iv[0] = 0x0
                else:
                    iv[0] += 1
            else:
                iv[1] += 1
        return ciphertext

    #input: bytestring, int[4], int[2]
    @staticmethod
    def decrypt(ciphertext, key, iv):
        key = [int(key[0]), int(key[1]), int(key[2]), int(key[3])]
        iv = [int(iv[0]), int(iv[1])]
        if len(ciphertext) % 8 != 0:
            print("Bad ciphertext length")
            return b""
        plaintext = b""
        for i in range(0, len(ciphertext), 8):
            temp = [int.from_bytes(ciphertext[i:i+4], "big"), int.from_bytes(ciphertext[i+4:i+8], "big")]
            (Ltemp, Rtemp) = tea_algorithm.TEA.encrypt(iv, key)
            plaintext += (Ltemp ^ temp[0]).to_bytes(4, "big")
            plaintext += (Rtemp ^ temp[1]).to_bytes(4, "big")
            if (iv[1] == 0xffffffff):
                iv[1] = 0x0
                if (iv[0] == 0xffffffff):
                    iv[0] = 0x0
                else:
                    iv[0] += 1
            else:
                iv[1] += 1
        return plaintext