import socket, random, threading, ast, os

# Encrypt data and return
def crypt(m, k): return "".join(chr(ord(i)^int(str(k), 16)) for i in m).encode()

# Return random number in range of seednumber
def rnd(): return random.randint(1337, 31337)

# Return random prime number
def prim():
  while True:
    p = random.randrange(10001, 100000, 2)
    if all(p % n != 0 for n in range(3, int((p ** 0.5) + 1), 2)): return p

# Handle connection and binding (client/server) and return the zocket
def connect(host, port, bind=False):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  if bind == False: sock.connect((host, port)); return sock
  else: sock.bind((host, port)); sock.listen(5); return sock

# Get a string value of the datalength, if byte we add 3 chrs for b''
def datalen(data):
  if type(data) is bytes: return str(len(data) + 3)
  return str(len(str(data)))

# Send a header with 64 bytes, which holds the length of the data & then data
def send(sock, data):
  # Fill the header with spaces to contain the exact number of 64 bytes
  hdr = "".join(" " for i in range(0, 64 - len(datalen(data)))) + datalen(data)
  sock.send(str(hdr).encode())
  sock.send(str(data).encode())

# Receive a header with 64 bytes, which holds the length of the data & then data
def recv(sock, b=False):
  rec = int(sock.recv(64).decode()) # Receive "header" containing msg length
  if b is True: return sock.recv(rec).decode()
  else: return sock.recv(rec)

# Thread loop catching possible Ctrl + c keys to break the server loop
def work(thrd):
  while thrd.is_alive():
    try: thrd.join(timeout=0.1)
    except (KeyboardInterrupt, SystemExit): threading.Event().set(); os._exit(9)

# Thread worker
def worker(fnc): t = threading.Thread(target=fnc, name=fnc); t.start(); work(t)

# Return the byte map
def liteval(b): return ast.literal_eval(b.decode())
