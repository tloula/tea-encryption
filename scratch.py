from tea_algorithm import TEA

def test():
    k = [0xbe168aa1, 0x16c498a3, 0x5e87b018, 0x56de7805]
    v = [1385482522, 639876499]

    l, r = TEA.decrypt(TEA.encrypt(v, k), k)

    print (l)
    print (r)