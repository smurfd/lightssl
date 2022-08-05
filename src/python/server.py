import time, threading, socket, sys, os

def crypt(msg, key):
  return bytes("".join(chr(ord(m) ^ int(key, 16)) for m in msg), 'utf-8')

def connect():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind(('127.0.0.1', 9999))
  s.listen(5)
  return s

def recv_hello(s):
  hello = s.recv(1024)
  print("hello:", hello)
  return hello

def recv_data(s):
  data = s.recv(1024)
  return data

def recv_key(s, key_len):
  key = s.recv(int(key_len))
  return key

def recv_key_len(s):
  key_len = s.recv(4)
  return key_len

def send_hello(s, hello):
  s.send(hello.encode())

def send_data(s, data):
  s.send(data)

def dowork():
  s = connect()
  work_loop(s)

def work_loop(s):
  while True:
    c,addr = s.accept()
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
  except (KeyboardInterrupt, SystemExit):
    shutdown_event.set()
    os._exit(9)

main()
