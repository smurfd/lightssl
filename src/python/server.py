# from https://github.com/luciangutu/tls_handshake_poc

import socket
import json
import binascii
from random import randint

hl = 64     # header length
f = 'utf-8' # format

serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind((socket.gethostbyname(socket.gethostname()),8080))

server_private_number = randint(1, 133700)
def crypt(msg, key):
  print("Encrypted message: {}".format(msg))
  crypt_msg = ''
  for c in msg: crypt_msg += chr(ord(c) ^ key)
  return str(binascii.hexlify(bytes(crypt_msg, f)), f)

print("Starting server...")
serv.listen(5)
while True:
  conn, addr = serv.accept()
  handshake = False
  while True:
    # getting the HEADER first. HEADER contains the message length
    find_msg_length = conn.recv(hl).decode(f)
    if not find_msg_length or find_msg_length == 0 : break
    data = conn.recv(int(find_msg_length)).decode(f)
    if not data: break
    if not handshake:
      # Diffie-Hellman handshake
      handshake = True
      g, n, client_param = [int(e) for e in json.loads(data)]
      server_key = (client_param ** server_private_number) % n
      server_param = (g ** server_private_number) % n
      conn.send(json.dumps(server_param).encode(f))
    else:
      print("Decrypted msg", bytes.fromhex(crypt(json.loads(data), server_key)).decode(f))
conn.close()
