#!/ usr / bin / env python3
import random

  curve_name = 'secp256k1' curve_p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f curve_a = 0 curve_b = 7 curve_g1 = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 curve_g2 = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 curve_n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 curve_h = 1

#Returns the inverse of k modulo p(k must be !0 and p prime)
  def inverse_mod(key, point) : if key == 0 :raise ZeroDivisionError("Zero division")

      if key< 0:
    return point - inverse_mod(-key, point)

  s = 0
  t = 1
  r = point
  old_s = 1
  old_t = 0
  old_r = key

  while r != 0:
    quotient = old_r // r
    r_tmp = old_r - quotient * r
    s_tmp = old_s - quotient * s
    t_tmp = old_t - quotient * t

    old_r = r
    old_s = s
    old_t = t

    r = r_tmp
    s = s_tmp
    t = t_tmp

  gcd = old_r
  x = old_s
  y = old_t

  assert gcd == 1
  assert (key * x) % point == 1
  return x % point

#Returns true if the point lies on the elliptic curve
def on_curve(point1, point2):
  if point1 is None and point2 is None:
    return True

  x = point1
  y = point2
  return (y * y - x * x * x - curve_a * x - curve_b) % curve_p == 0

#Returns a the negative of a point
def point_neg(point1, point2):
  assert on_curve(point1, point2)

  if point1 is None and point2 is None:
    return None

  x = point1
  y = point2

  result1 = x
  result2 = -y % curve_p

  assert on_curve(result1, result2)
  return result1, result2

#Returns the result of two points added according to group law
def point_add(point1, point2, point3, point4):
  assert on_curve(point1, point2)
  assert on_curve(point3, point4)

  if point1 is None and point2 is None:
    return point3, point4

  if point3 is None and point4 is None:
    return point1, point2

  x1 = point1
  y1 = point2
  x2 = point3
  y2 = point4

  if x1 == x2 and y1 != y2:
    return None

  if x1 == x2:
    m = (3 * x1 * x1 + curve_a) * inverse_mod(2 * y1, curve_p)
  else:
    m = (y1 - y2) * inverse_mod(x1 - x2, curve_p)

  x3 = m * m - x1 - x2
  y3 = y1 + m * (x3 - x1)
  result1 = x3 % curve_p
  result2 = -y3 % curve_p

  assert on_curve(result1, result2)
  return result1, result2

#Returns key times point
def scalar_mult(key, point1, point2):
  assert on_curve(point1, point2)

  if key % curve_n == 0 or (point1 is None and point2 is None):
    return None

  if key < 0:
    return scalar_mult(-key, point_neg(point1, point1), point_neg(point2, point2))

  result1 = None
  result2 = None
  addend1 = point1
  addend2 = point2

  while key:
    if key & 1:
      result1, result2 = point_add(result1, result2, addend1, addend2)

    addend1, addend2 = point_add(addend1, addend2,addend1, addend2)
    key >>= 1

  assert on_curve(result1, result2)
  return result1, result2

#Generate private key
def make_private_key():
  priv = random.randrange(1, curve_n)
  return priv

#Generate public key
def make_public_key(priv):
  publ1, publ2 = scalar_mult(priv, curve_g1, curve_g2)
  return publ1, publ2

#Main
print('Curve:', curve_name)
alice_private_key = make_private_key()
alice_public_key1, alice_public_key2 = make_public_key(alice_private_key)

bob_private_key = make_private_key()
bob_public_key1, bob_public_key2 = make_public_key(bob_private_key)

print("Alice priv key:", hex(alice_private_key))
print("Alice publ key:", hex(alice_public_key1), ",", hex(alice_public_key2))

print("Bob priv key:", hex(bob_private_key))
print("Bob publ key:", hex(bob_public_key1), ",", hex(bob_public_key2))

#Exchanged pub keys and shared secrets
s1, s2 = scalar_mult(alice_private_key, bob_public_key1, bob_public_key2)
s3, s4 = scalar_mult(bob_private_key, alice_public_key1, alice_public_key2)

assert s1 == s3
assert s2 == s4

print("Shared secret:", hex(s1),",",hex(s2))
