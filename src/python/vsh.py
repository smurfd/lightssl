import socket, random, threading, ast, os

def crypt(m, k): return "".join(chr(ord(i)^int(str(k), 16)) for i in m).encode()

def rnd(r): return random.randint(1, r)

def connect(host, port, bind=False):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  if bind == False: s.connect((host, port))
  else: s.bind((host, port)); s.listen(5)
  return s

def calc_data_length(data):
  if type(data) is bytes: return len(data) + 3 # +3 is for b''
  return len(str(data))

def send(s, data):
  ss = str(calc_data_length(data))
  ss = "".join(" " for i in range(0, 64 - len(ss))) + ss
  s.send(str(ss).encode()) # Send "header" containing msg length
  s.send(str(data).encode())

def recv(s, b=False):
  rec = int(s.recv(64).decode()) # Receive "header" containing msg length
  if b is True: return s.recv(rec).decode()
  else: return s.recv(rec)

def work(t):
  while t.is_alive():
    try: t.join(timeout=0.1)
    except (KeyboardInterrupt, SystemExit): threading.Event().set(); os._exit(9)

def worker(tt): t = threading.Thread(target=tt, name=tt); t.start(); work(t)

def ast_lit(b): return ast.literal_eval(b.decode())
