import vsh

# Main function
def main():
  sock = vsh.connect('127.0.0.1', 9999, bind=False)
  g, n, p = vsh.rnd(), vsh.rnd(), vsh.rnd()
  cp = (g ** p) % n
  # Send parameters then send encrypted data
  vsh.send(sock, ([str(g), str(n), str(cp)]))
  vsh.send(sock, vsh.crypt("Secret1234", str(((int(vsh.recv(sock))) ** p) % n)))
  sock.close()

main()
