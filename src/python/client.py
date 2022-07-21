# from https://github.com/luciangutu/tls_handshake_poc

import socket
import json
import binascii
from random import randint

hl = 64     # header length
f = 'utf-8' # format
message = "secret, secret, super secret"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((socket.gethostbyname(socket.gethostname()), 8080))

def send(msg):
  ml = str(len(msg.encode(f))).encode(f) +\
    (b' ' * (hl - len(str(len(msg.encode(f))).encode(f))))
  client.send(ml)
  client.send(msg.encode(f))
  return msg.encode(f)

def crypt(msg, key):
  crypt_msg = ''
  for c in msg: crypt_msg += chr(ord(c) ^ key)
  return str(binascii.hexlify(bytes(crypt_msg, f)), f)

g, n, p = randint(1, 133700), randint(1, 133700), randint(1, 133700)
client_param = (g ** p) % n

# Diffie-Hellman handshake, serialize the g, n and client parameter
send(json.dumps([str(g), str(n), str(client_param)]))
from_server = client.recv(2048)
server_param = json.loads(from_server)
client_key = (server_param ** p) % n

print(send(json.dumps(crypt(message, client_key))))

client.close()
