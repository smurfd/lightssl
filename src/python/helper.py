import socket, random, threading, ast, os

def crypt(m, k): return "".join(chr(ord(i) ^ int(k, 16)) for i in m).encode()

def rnd(r): return random.randint(1, r)

def connect(bind=False):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  if bind == False:
    s.connect(('127.0.0.1', 9999))
  else:
    s.bind(('127.0.0.1', 9999))
    s.listen(5)
  return s

def calc_data_length(data):
  if type(data) is bytes: return len(data) + 3 # +3 is for b''
  else: return len(str(data))

def send(s, data):
  ss = str(calc_data_length(data))
  ss = "".join(" " for i in range(0, 64 - len(ss))) + ss
  s.send(str(ss).encode())
  s.send(str(data).encode())

def recv(s): return s.recv(int(s.recv(64).decode()))

def worker(tt):
  t = threading.Thread(target=tt, args=(), name='worker')
  t.start()
  try:
    while t.is_alive(): t.join(timeout=0.1)
  except (KeyboardInterrupt, SystemExit): threading.Event().set(); os._exit(9)

def ast_lit(b): return ast.literal_eval(b.decode())
