import vsh

# Server loop
def srvloop(): listenloop(vsh.connect('127.0.0.1', 9999, bind=True))

# Loop that listens for connections from the client
def listenloop(sock):
  while True: c, addr = sock.accept(); shakeloop(c, vsh.prim()); c.close()

# The loop within the loop that handles the handshake
def shakeloop(c, priv, shake=False):
  while True:
    if not shake:
      shake = True
      g, p, ap = map(int, vsh.liteval(vsh.recv(c)))
      vsh.send(c, str((g ** priv) % p)) # Send bobs public key
    else: vsh.crypt(vsh.recv(c, b=True), (ap ** priv) % p); break
    # Exit after handshake, data is transfered encrypted
    # ap = alices public key, g & p shared public values
    # (g ** priv) % p = bobs public key
    # (ap ** priv) % p = shared secret

# Main function
def main(): vsh.worker(srvloop)

main()
