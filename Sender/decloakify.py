import sys
import base64
import binascii
import os

array64 = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=�")

def Decloakify(arg1, arg2, arg3):
    if os.path.exists(arg1) == False or os.path.exists(arg2) == False:
        return -1
    with open(arg1) as file:
        listExfiltrated = file.readlines()
        
    with open(arg2) as file:
        arrayCipher = file.readlines()
        
    clear64 = ""
    
    #Per ogni parola, trova l'indice della parola in arrayCipher, 
    #quindi utilizza questo indice per accedere a un elemento corrispondente in una lista chiamata array64.
    #La stringa risultante viene concatenata a clear64.
    for word in listExfiltrated:
        clear64 += array64[arrayCipher.index(word)]
    # Ensure correct base64 padding
    clear64 = clear64.rstrip('\n')  # Remove trailing newline
    padding_needed = len(clear64) % 4
    if padding_needed:
        clear64 += '=' * (4 - padding_needed)
    try:
        decoded_string = base64.b64decode(clear64).decode('utf-8')
    except:
        return -1
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
