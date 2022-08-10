import vsh

def main():
  message = "secret, secret, super secret"
  s = vsh.connect(bind=False)
  vsh.send(s, "Hello")
  g, n, p = vsh.rnd(31337), vsh.rnd(31337), vsh.rnd(31337)
  cp = (g ** p) % n + int("0x31337", 16)
  if vsh.recv(s) == "olleH".encode():
    vsh.send(s, "0x31337")
    vsh.send(s, ([str(g), str(n), str(cp)]))
    vsh.send(s, vsh.crypt(message,str(((int(vsh.recv(s))) ** p) % n)))
  s.close()

main()
