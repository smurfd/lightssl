import vsh

# Main function
def main():
  sock = vsh.connect('127.0.0.1', 9999, bind=False)
  g, p, priv = vsh.prim(), vsh.prim(), vsh.prim()

  ap = (g ** priv) % p # Alice public key
  # Send parameters then send encrypted data
  vsh.send(sock, ([str(g), str(p), str(ap)]))
  bp = int(vsh.recv(sock)) # Receive bobs public key
  vsh.send(sock, vsh.crypt("Secret1234", str(((bp) ** priv) % p)))
  print("alis pub :", (g ** priv) % p)
  print("bobs pub :", bp)
  print("share :", (bp ** priv) % p)
  sock.close()

main()
