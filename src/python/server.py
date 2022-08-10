import helper

def dowork(): work_loop(helper.connect(bind=True))

def work_loop(s):
  priv = helper.rnd(31337)
  while True:
    c, addr = s.accept()
    shake = False
    if helper.recv(c) == "Hello".encode():
      helper.send(c, "olleH")
      if not shake:
        shake = True
        key = helper.recv(c)
        g, n, cp = map(int, helper.ast_lit(helper.recv(c)))
        cp -= int(key, 16)
        helper.send(c, str((g ** priv) % n))
      else: helper.crypt(helper.recv(c), (cp ** priv) % n)
    c.close()

def main(): helper.worker(dowork)

main()
