import lightcrypto, socket, random, math

def lightcrypto_rand():
  r = 0
  for i in range(0, 5): r = (r << 15) | (random.randint(0, 31337) & 0x7FFF)
  return r & 0xFFFFFFFFFFFFFFFF

def lightcrypto_genkeys(g, p):
  priv = lightcrypto_rand()
  return priv, pow(g, priv, p)

def lightcrypto_genshare(priv1, publ1, priv2, publ2, p, s=False):
  if not s: return p % pow(publ1, priv2)
  else: return p % pow(publ2, priv1)

def lightcrypto_crypt(data, s1): return data ^ s1

def keys():
  random.seed(31337)
  g1 = lightcrypto_rand(); g2 = lightcrypto_rand()
  p1 = lightcrypto_rand(); p2 = lightcrypto_rand()
  c = 123456; d = 0; e = 0

  priv1, pub1 = lightcrypto_genkeys(g1, p1)
  priv2, pub2 = lightcrypto_genkeys(g2, p2)
  s1 = lightcrypto_genshare(priv1, pub1, priv2, pub2, p1, s=False)
  s2 = lightcrypto_genshare(priv1, pub1, priv2, pub2, p1, s=True)
  print("Alice public & private key:", hex(pub1), hex(priv1))
  print("Bobs public & private key:", hex(pub2), hex(priv2))
  print("Alice & Bobs shared key:", hex(s1), hex(s2))
  d = lightcrypto_crypt(c, s1)
  e = lightcrypto_crypt(d, s2)
  assert(c == e)

# Main function
def main():
  try:
    sock = lightcrypto.connect('127.0.0.1', 9999, bind=False)
    g, p, priv = lightcrypto.prim(), lightcrypto.prim(), lightcrypto.prim()

    # Send parameters then send encrypted data
    lightcrypto.send(sock, ([str(g), str(p), str((g ** priv) % p)]))
    lightcrypto.send(sock, lightcrypto.crypt("Secret1",
      str(((int(lightcrypto.recv(sock))) ** priv) % p)))
    sock.close()
    lightcrypto.keypair()
    # (g ** priv) % p = alices public key, g & p shared public values
    # int(lightcrypto.recv(sock)) = bobs public key
    # (((int(lightcrypto.recv(sock))) ** priv) % p) = shared secret
  except socket.error:
    keys()

main()
