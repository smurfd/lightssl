import vsh

def main():
  message = "secret, secret, super secret"
  s = vsh.connect(bind=False)
  g, n, p = vsh.rnd(31337), vsh.rnd(31337), vsh.rnd(31337)
  cp = (g ** p) % n
  vsh.send(s, ([str(g), str(n), str(cp)]))
  vsh.send(s, vsh.crypt(message,str(((int(vsh.recv(s))) ** p) % n)))
  s.close()

main()
