import vsh

# Server loop
def srvloop(): listenloop(vsh.connect('127.0.0.1', 9999, bind=True))

# Loop that listens for connections from the client
def listenloop(sock):
  while True:
    c, addr = sock.accept()
    shakeloop(c, vsh.rnd())
    c.close()

# The loop within the loop that handles the handshake
def shakeloop(c, priv, shake=False):
  while True:
    if not shake:
      shake = True
      g, n, cp = map(int, vsh.liteval(vsh.recv(c)))
      vsh.send(c, str((g ** priv) % n))
    else: vsh.crypt(vsh.recv(c, b=True), (cp ** priv) % n); break
    # We break after crypt because handshake is done and data
    # is transfered encrypted

# Main function
def main(): vsh.worker(srvloop)

main()
