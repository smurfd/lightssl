import socket, random, helper

def main():
  message = "secret, secret, super secret"
  s = helper.connect()
  helper.send(s, "Hello")
  g, n, p = random.randint(1,1337),random.randint(1,1337),random.randint(1,1337)
  key = "0x31337"
  cp = (g ** p) % n + int(key, 16)
  if helper.recv(s) == "olleH".encode():
    helper.send(s, key)
    helper.send(s, ([str(g), str(n), str(cp)]))
    helper.send(s, helper.crypt(message,str(((int(helper.recv(s))) ** p) % n)))
  s.close()

main()
