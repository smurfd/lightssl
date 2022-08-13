import vsh

def dowork(): work_loop(vsh.connect('127.0.0.1', 9999, bind=True))

def work_loop(s):
  while True:
    priv = vsh.rnd(31337)
    shake = False
    c, addr = s.accept()
    while True:
      if not shake:
        shake = True
        recv = vsh.recv(c)
        g, n, cp = map(int, vsh.ast_lit(recv))
        vsh.send(c, str((g ** priv) % n))
      else: vsh.crypt(vsh.recv(c, b=True), (cp ** priv) % n); break
      # We break after crypt because handshake is done and data
      # is transfered encrypted
    c.close()

def main(): vsh.worker(dowork)

main()
