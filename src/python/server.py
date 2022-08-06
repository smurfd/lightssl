import time, threading, socket, sys, os

def crypt(m, k): return "".join(chr(ord(i) ^ int(k, 16)) for i in m).encode()

def connect():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind(('127.0.0.1', 9999))
  s.listen(5)
  return s

def recv_hello(s):
  return s.recv(1024)

def recv_data(s):
  return s.recv(1024)

def recv_key(s, key_len):
  return s.recv(int(key_len))

def recv_key_len(s):
  return s.recv(4)

def send_hello(s, hello):
  s.send(hello.encode())

def send_data(s, data):
  s.send(data)

def dowork():
  work_loop(connect())

def work_loop(s):
  while True:
    c, addr = s.accept()
    if recv_hello(c) == "Hello".encode():
      send_hello(c, "olleH")
      key_len = recv_key_len(c)
      key = recv_key(c, key_len)
      data = recv_data(c)
      send_data(c, crypt("Other Sup3r S3cr3t sh1t", key))
    c.close()

def main():
  shutdown_event = threading.Event()
  t = threading.Thread(target=dowork, args=(), name='worker')
  t.start()

  try:
    while t.is_alive(): t.join(timeout=0.1)
  except (KeyboardInterrupt, SystemExit): shutdown_event.set(); os._exit(9)

main()
