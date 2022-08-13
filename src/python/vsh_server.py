import vsh

def dowork(): work_loop(vsh.connect(bind=True))

def work_loop(s):
  while True:
    priv = vsh.rnd(31337)
    shake = False
    c, addr = s.accept()
    while True:
      if not shake:
        shake = True
        recv = vsh.recv(c)
        if not recv or recv == 0 or recv == False: break
        g, n, cp = map(int, vsh.ast_lit(recv))
        vsh.send(c, str((g ** priv) % n))
      else: vsh.crypt(vsh.recv(c, b=True).decode(), (cp ** priv) % n); break
    c.close()

def main(): vsh.worker(dowork)

main()
