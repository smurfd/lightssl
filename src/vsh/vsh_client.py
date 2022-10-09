import vsh, socket, random, math

def vsh_rand():
  r = 0
  for i in range(0, 5): r = (r << 15) | (random.randint(0, 31337) & 0x7FFF)
  return r & 0xFFFFFFFFFFFFFFFF

def vsh_genkeys(g, p):
  priv = vsh_rand()
  return priv, pow(g, priv, p)

def vsh_genshare(priv1, publ1, priv2, publ2, p, s=False):
  if not s: return p % pow(publ1, priv2)
  else: return p % pow(publ2, priv1)

def vsh_crypt(data, s1): return data ^ s1

def keys():
  random.seed(31337)
  g1 = vsh_rand(); g2 = vsh_rand()
  p1 = vsh_rand(); p2 = vsh_rand()
  c = 123456; d = 0; e = 0

  priv1, pub1 = vsh_genkeys(g1, p1)
  priv2, pub2 = vsh_genkeys(g2, p2)
  s1 = vsh_genshare(priv1, pub1, priv2, pub2, p1, s=False)
  s2 = vsh_genshare(priv1, pub1, priv2, pub2, p1, s=True)
  print("Alice public & private key:", hex(pub1), hex(priv1))
  print("Bobs public & private key:", hex(pub2), hex(priv2))
  print("Alice & Bobs shared key:", hex(s1), hex(s2))
  d = vsh_crypt(c, s1)
  e = vsh_crypt(d, s2)
  assert(c == e)

# Main function
def main():
  try:
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
  except socket.error:
    keys()

main()
