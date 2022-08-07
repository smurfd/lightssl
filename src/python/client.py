import socket, random, helper

def main():
  message = "secret, secret, super secret"
  s = helper.connect()
  helper.send_stuff(s, "Hello")
  g, n, p = random.randint(1, 1337), random.randint(1, 1337), random.randint(1, 1337)
  cp = (g ** p) % n
  if helper.recv_stuff(s) == "olleH".encode():
    helper.send_stuff(s, "0x31337")
    helper.send_stuff(s, ([str(g), str(n), str(cp)]))
    helper.send_stuff(s, helper.crypt(message,str(((int(helper.recv_stuff(s))) ** p) % n)))

  s.close()

main()
