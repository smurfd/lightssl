import helper

def main():
  message = "secret, secret, super secret"
  s = helper.connect(bind=False)
  helper.send(s, "Hello")
  g, n, p = helper.rnd(31337), helper.rnd(31337), helper.rnd(31337)
  cp = (g ** p) % n + int("0x31337", 16)
  if helper.recv(s) == "olleH".encode():
    helper.send(s, "0x31337")
    helper.send(s, ([str(g), str(n), str(cp)]))
    helper.send(s, helper.crypt(message,str(((int(helper.recv(s))) ** p) % n)))
  s.close()

main()
