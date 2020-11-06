from Crypto import Random
from Crypto.Cipher import AES
import base64
import binascii
import socket
import sys
import time

HOST = '127.0.0.1'
PORT = 4444


def xor(x1, x2): 
    return bytearray(a^b for a, b in zip(*map(bytearray, [x1, x2]))) 


flag_enc = binascii.unhexlify("b398bffadbdad3f1d2f2ff75f55babf7d775f9eb8988c97d70bb2e4db447f746d52c88a6681ab225fbafcaa480e0db88f8709828263ad3af83ba50d6348b49900e6c7db4cfedf7ff701c61743cacf587")
flag=''


red="\033[1;31;40m"
green = "\033[1;32;40m"
gray = "\033[1;30;40m"
normal = "\033[0;37;40m"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    data = s.recv(1024)
    for i in range(0,len(flag_enc)):
        print(">>> ", end='')
        pld = flag + '\x00' + "\r\n"
        s.send(pld.encode())
        print(green + pld + normal)
        
        time.sleep(0.1)
        r = s.recv(1024)
        r = r.decode().split('\n')
        print(gray + r[0] + normal)
        c = binascii.unhexlify(r[0])
        flag+=chr(c[i]^flag_enc[i])
        sys.stdout.write("\033[F\033[F\033[F")
        
print("\n\n")

