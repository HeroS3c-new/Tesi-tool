import sys
import base64

array64 = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=")

def Decloakify(arg1, arg2, arg3):
    with open(arg1) as file:
        listExfiltrated = file.readlines()
        
    with open(arg2) as file:
        arrayCipher = file.readlines()
        
    clear64 = ""
    for word in listExfiltrated:
        clear64 += array64[arrayCipher.index(word)]
        
    decoded_string = base64.b64decode(clear64).decode('utf-8')

    if arg3 != "":
        with open(arg3, "w") as outFile:
            outFile.write(decoded_string)
    else:
        print(decoded_string, end=' ')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: decloakify.py <cloakedFilename> <cipherFilename>")
        sys.exit(1)
    else:
        Decloakify(sys.argv[1], sys.argv[2], "decrypted_command.txt")
