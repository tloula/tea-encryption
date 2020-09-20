# Tiny Encryption Algorithm Implementation
# Ian Bolin & Trevor Loula
# CS-3350 Foundations of Computer Security

import sys
from tea_algorithm import TEA

class Wrapper:
    pass

def main(args):
    k = [0xbe168aa1, 0x16c498a3, 0x5e87b018, 0x56de7805]
    v = [1385482522, 639876499]

    l, r = TEA.decrypt(TEA.encrypt(v, k), k)

    print (l)
    print (r)

if __name__ == "__main__":
    main(sys.argv)