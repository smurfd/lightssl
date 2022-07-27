# from https://github.com/luciangutu/tls_handshake_poc

import socket
import json
import binascii as bi
from random import randint

hl = 64     # header length
f = 'utf-8' # format
message = "secret, secret, super secret"

def mkcon():
  client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  client.connect((socket.gethostbyname(socket.gethostname()), 8080))
  return client

def send(client, msg):
  ml = str(len(msg.encode(f))).encode(f) +\
    (b' ' * (hl - len(str(len(msg.encode(f))).encode(f))))
  client.send(ml)
  client.send(msg.encode(f))
  return msg.encode(f)

def crypt(msg, key):
  return str(bi.hexlify(bytes("".join(chr(ord(c) ^ key) for c in msg), f)), f)

def main():
  cl = mkcon()
  g, n, p = randint(1, 133700), randint(1, 133700), randint(1, 133700)
  client_param = (g ** p) % n

  # Diffie-Hellman handshake, serialize the g, n and client parameter
  send(cl, json.dumps([str(g), str(n), str(client_param)]))
  print("".join(chr(x) for x in send(cl, json.dumps(crypt(message,
    (json.loads(cl.recv(2048)) ** p) % n)))))

  cl.close()

main()
