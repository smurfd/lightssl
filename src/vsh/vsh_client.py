import vsh

# Main function
def main():
  sock = vsh.connect('127.0.0.1', 9999, bind=False)
  g, p, priv = vsh.prim(), vsh.prim(), vsh.prim()

  # Send parameters then send encrypted data
  vsh.send(sock, ([str(g), str(p), str((g ** priv) % p)]))
  vsh.send(sock, vsh.crypt("Secret1", str(((int(vsh.recv(sock))) ** priv) % p)))
  sock.close()

  vsh.keypair()
  # (g ** priv) % p = alices public key, g & p shared public values
  # int(vsh.recv(sock)) = bobs public key
  # (((int(vsh.recv(sock))) ** priv) % p) = shared secret

main()
