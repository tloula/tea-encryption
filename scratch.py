from tea_algorithm import TEA
from tea_cbc import TEA_CBC

def test():
    k = [0xbe168aa1, 0x16c498a3, 0x5e87b018, 0x56de7805]
    v = [1385482522, 639876499]

    l, r = TEA.decrypt(TEA.encrypt(v, k), k)

    print (l)
    print (r)

    iv = [32, 64]
    v = b"abcdefghabcdefghabcdefghabcdefgh"
    ciphertext = TEA_CBC.encrypt(v, k, iv)
    print(ciphertext)
    print(len(ciphertext))
    print(iv)
    print(v)
    print(len(v))
    plaintext = TEA_CBC.decrypt(ciphertext, k, iv)
    print(ciphertext)
    print(iv)
    print(v)
    print(plaintext)
    print(len(plaintext))

test()