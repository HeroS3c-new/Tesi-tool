import os
import sys
import base64

array64 = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=")

def Cloakify(arg1, arg2, arg3):
    payloadB64 = base64.encodebytes(arg1.encode('utf-8'))
    
    try:
        with open(arg2) as file:
            cipherArray = file.readlines()
    except Exception as e:
        print(f"!!! Oh noes! Problem reading cipher '{arg2}': {e}")
        print("!!! Verify the location of the cipher file")
        return
    
    if arg3 != "":
        file_path = os.path.abspath(arg3)
        try:
            with open(file_path, "w+") as outFile:
                for char in payloadB64.decode('utf-8'):
                    if char != '\n':
                        outFile.write(cipherArray[array64.index(char)])
                outFile.write('endOfTransmission.google.com')
        except Exception as e:
            print(f"!!! Oh noes! Problem opening or writing to file '{file_path}': {e}")
            return
    else:
        for char in payloadB64.decode('utf-8'):
            if char != '\n':
                print(cipherArray[array64.index(char)], end=' ')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: cloakify.py <payloadFilename> <cipherFilename>")
        sys.exit(1)
    else:
        Cloakify(sys.argv[1], sys.argv[2], "cloaked_command.txt")
