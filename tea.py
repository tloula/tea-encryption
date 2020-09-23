# ********************************************* #
# Tiny Encryption Algorithm Implementation      #
# Ian Bolin & Trevor Loula                      #
# CS-3350 Foundations of Computer Security      #
# ********************************************* #

import sys
from tea_cbc import TEA_CBC
from tea_ctr import TEA_CTR
from tea_ecb import TEA_ECB

class Wrapper:

    @staticmethod
    def parse_input(args):
        mode = args[1][1:3]
        cipher = args[2][1:4]
        text = Wrapper.read_file(args[3])
        key = Wrapper.read_file(args[4])
        iv = Wrapper.read_file(args[5])

        keys = [x for x in Wrapper.split_string(key)]
        ivs = [x for x in Wrapper.split_string(iv)]

        return mode, cipher, text, keys, ivs

    @staticmethod
    def read_file(filepath):
        try:
            f = open(filepath, "rt")
        except FileNotFoundError as e:
            print ("File", filepath, "not found")
            exit()
        else:
            try:
                text = f.read()
                if "-H" in filepath:
                    text = Wrapper.pad_hex(text)
                    return text.decode("hex")
                else:
                    text = Wrapper.pad_text(text)
                    return text.encode()
            finally:
                f.close()

    @staticmethod
    def pad_text(text):
        while len(text) % 8 != 0:
            text += " "

        return text

    @staticmethod
    def pad_hex(hex):
        while len(hex) % 8 != 0:
            hex += "0"

        return hex

    @staticmethod
    def split_string(s):
        n = 8
        return [s[i:i+n] for i in range(0, len(s), n)]

    @staticmethod
    def run_tea(params):
        mode, cipher, text, key, iv = params

        print ("cipher:", cipher)   # ECB, CBC, or CTR
        print ("text:", text)       # The Plaintext or Ciphertext
        print ("key:", key)         # Key
        print ("iv:", iv)           # Initialization Vector

        if cipher == "ECB":
            if mode == "e":
                print (TEA_ECB.encrypt(text, key))
            elif mode == "d":
                print (TEA_ECB.decrypt(text, key))
            else:
                print ("Invalid operation mode")
        elif cipher == "CBC":
            if mode == "e":
                print (TEA_CBC.encrypt(text, key, iv))
            elif mode == "d":
                print (TEA_CBC.decrypt(text, key, iv))
            else:
                print ("Invalid operation mode")
        elif cipher == "CTR":
            if mode == "e":
                print (TEA_CTR.encrypt(text, key, iv))
            elif mode == "d":
                print (TEA_CTR.decrypt(text, key, iv))
            else:
                print ("Invalid operation mode")
        else:
            print("Invalid Mode")
            exit()

        return

def main(args):

    # python tea.py -e -ECB  assignment-files/Practice/practice_ECB-H.plain assignment-files/teacher-H.key assignment-files/teacher-H.iv

    if len(args) != 6:
        print("Usage: python tea.py -mode -cipher plaintext key initialization_vector")
        print("-mode: -e, -d")
        print("-cipher: ECB, CBC, CTR")
        print("i.e. python tea.py -e -ECB plaintext.plain key.key initialization_vector.iv")
        exit()

    Wrapper.run_tea(Wrapper.parse_input(args))

if __name__ == "__main__":
    main(sys.argv)
