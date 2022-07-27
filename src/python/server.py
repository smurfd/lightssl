# from https://github.com/luciangutu/tls_handshake_poc

import socket
import json
import binascii as bi
from random import randint

hl = 64     # header length
f = 'utf-8' # format

def crypt(msg, key):
  print("Encrypted message:", msg)
  return str(bi.hexlify(bytes("".join(chr(ord(c) ^ key) for c in msg), f)), f)

def srvcon():
  serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  serv.bind((socket.gethostbyname(socket.gethostname()),8080))
  return serv

def srvloop():
  sr = srvcon()
  sr.listen(5)
  srvprivnr = randint(1, 133700)
  while True:
    conn, addr = sr.accept()
    handshake = False
    while True:
      # getting the HEADER first. HEADER contains the message length
      msglen = conn.recv(hl).decode(f)
      if not msglen or msglen == 0: break
      data = conn.recv(int(msglen)).decode(f)
      if not data: break
      if not handshake:
        # Diffie-Hellman handshake
        handshake = True
        g, n, cliparm = [int(e) for e in json.loads(data)]
        conn.send(json.dumps((g ** srvprivnr) % n).encode(f)) # server_param
      else: # server_key = (cliparm ** srvprivnr) % n
        print("Decr", crypt(json.loads(data), (cliparm ** srvprivnr) % n))
  conn.close()

print("Starting server...")
srvloop()
