# Tiny Encryption Algorithm Implementation
# Ian Bolin & Trevor Loula
# CS-3350 Foundations of Computer Security

import sys
from ctypes import *

class TEA:

    @staticmethod
    def encrypt(v, k):
        l = c_uint32(v[0])
        r = c_uint32(v[1])
        delta = 0x9e3779b9
        sum = c_uint32(0)

        for i in range (0, 32):
            sum.value += delta
            l.value = l.value + (((r.value << 4) + k[0]) ^ (r.value + sum.value) ^ ((r.value >> 5) + k[1]))
            r.value = r.value + (((l.value << 4) + k[2]) ^ (l.value + sum.value) ^ ((l.value >> 5) + k[3]))

        return l.value, r.value

    @staticmethod
    def decrypt(v, k):
        l = c_uint32(v[0])
        r = c_uint32(v[1])
        delta = 0x9e3779b9
        sum = c_uint32(delta << 5)

        for i in range (0, 32):
            r.value = r.value - (((l.value << 4) + k[2]) ^ (l.value + sum.value) ^ ((l.value >> 5) + k[3]))
            l.value = l.value - (((r.value << 4) + k[0]) ^ (r.value + sum.value) ^ ((r.value >> 5) + k[1]))
            sum.value -= delta

        return l.value, r.value
