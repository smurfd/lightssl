import lightcrypto

# Server loop
def srvloop(): listenloop(lightcrypto.connect('127.0.0.1', 9999, bind=True))

# Loop that listens for connections from the client
def listenloop(sock):
  while True: c, addr = sock.accept(); shakeloop(c, lightcrypto.prim()); c.close()

# The loop within the loop that handles the handshake
def shakeloop(c, priv, shake=False):
  while True:
    if not shake:
      shake = True
      g, p, ap = map(int, lightcrypto.liteval(lightcrypto.recv(c)))
      lightcrypto.send(c, str((g ** priv) % p)) # Send bobs public key
    else: lightcrypto.crypt(lightcrypto.recv(c, b=True), (ap ** priv) % p); break
    # Exit after handshake, data is transfered encrypted
    # ap = alices public key, g & p shared public values
    # (g ** priv) % p = bobs public key
    # (ap ** priv) % p = shared secret

# Main function
def main(): lightcrypto.worker(srvloop)

main()
