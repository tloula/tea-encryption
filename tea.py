# ********************************************* #
# Tiny Encryption Algorithm Implementation      #
# Ian Bolin & Trevor Loula                      #
# CS-3350 Foundations of Computer Security      #
# ********************************************* #

import sys
from tea_algorithm import TEA

class Wrapper:

    @staticmethod
    def parse_input(args):
        mode = args[1][1:3]
        cipher = args[2][1:4]
        text = Wrapper.read_file(args[3])
        key = Wrapper.read_file(args[4])
        iv = Wrapper.read_file(args[5])

        return mode, cipher, text, key, iv

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
                text = Wrapper.pad_text(text)
                if "-H" in filepath:
                    text = Wrapper.convert_hex(text)
                return text
            finally:
                f.close()

    @staticmethod
    def pad_text(text):
        while len(text) % 16 != 0:
            text += " "

        return text

    @staticmethod
    def convert_hex(hex):
        return int(hex, 16)

    @staticmethod
    def run_tea(params):
        mode, cipher, text, key, iv = params

        print ("cipher:", cipher)   # ECB, CBC, or CTR
        print ("text:", text)       # The Plaintext or Ciphertext
        print ("key:", key)         # Key
        print ("iv:", iv)           # Initialization Vector

        if mode == "e":
            print ("Encrypting")
            # Pass Ian a Byte String
            # TODO
            print (text.to_bytes((text.bit_length() + 7) // 8, 'big')) # ?
        elif mode == "d":
            print ("Decrypting")
        else:
            print ("Invalid operation mode")
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