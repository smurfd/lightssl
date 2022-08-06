import socket

def crypt(m, k): return "".join(chr(ord(i) ^ int(k, 16)) for i in m).encode()

def connect():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(('127.0.0.1', 9999))
  return s

def send_hello(s, hello):
  s.send(hello.encode())

def send_key(s, key):
  s.send(key.encode())

def send_key_len(s, key_len):
  s.send(key_len.encode())

def send_data(s, data):
  s.send(data)

def recv_hello(s):
  return s.recv(1024)

def main():
  s = connect()
  send_hello(s, "Hello")
  if recv_hello(s) == "olleH".encode():
    send_key_len(s, "0007")
    send_key(s, "0x31337")
    send_data(s, crypt("Sup3r S3cr3t sh1t", "0x31337"))
  s.close()

main()
