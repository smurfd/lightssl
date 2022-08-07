import time, threading, socket, sys, os, random, ast, helper

def dowork():
  work_loop(helper.bind())

def work_loop(s):
  priv = random.randint(1, 1337)
  while True:
    c, addr = s.accept()
    shake = False
    if helper.recv_stuff(c) == "Hello".encode():
      helper.send_stuff(c, "olleH")
      if not shake:
        key = helper.recv_stuff(c)
      else: data = helper.recv_stuff(c)
      if not shake:
        shake = True
        g, n, cp = map(int, ast.literal_eval(helper.recv_stuff(c).decode()))
        helper.send_stuff(c, str((g ** priv) % n))
      else:
        helper.crypt(data, (cp ** priv) % n)
    c.close()

def main():
  shutdown_event = threading.Event()
  t = threading.Thread(target=dowork, args=(), name='worker')
  t.start()

  try:
    while t.is_alive(): t.join(timeout=0.1)
  except (KeyboardInterrupt, SystemExit): shutdown_event.set(); os._exit(9)

main()
