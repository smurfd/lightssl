import socket

def crypt(m, k): return "".join(chr(ord(i) ^ int(k, 16)) for i in m).encode()

def connect():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(('127.0.0.1', 9999))
  return s

def bind():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind(('127.0.0.1', 9999))
  s.listen(5)
  return s

def calc_data_length(data):
  if type(data) is bytes: return len(data) + 3 #3 is for b''
  elif type(data) is str: return len(data)
  else: return len(str(data))

def send(s, data):
  ss = str(calc_data_length(data))
  ss = "".join(" " for i in range(0,64 - len(ss))) + ss
  s.send(str(ss).encode())
  s.send(str(data).encode())

def recv(s): return s.recv(int(s.recv(64).decode()))
