import vsh

def dowork(): work_loop(vsh.connect(bind=True))

def work_loop(s):
  priv = vsh.rnd(31337)
  while True:
    c, addr = s.accept()
    shake = False
    if vsh.recv(c) == "Hello".encode():
      vsh.send(c, "olleH")
      if not shake:
        shake = True
        key = vsh.recv(c)
        g, n, cp = map(int, vsh.ast_lit(vsh.recv(c)))
        cp -= int(key, 16)
        vsh.send(c, str((g ** priv) % n))
      else: vsh.crypt(vsh.recv(c), (cp ** priv) % n)
    c.close()

def main(): vsh.worker(dowork)

main()
