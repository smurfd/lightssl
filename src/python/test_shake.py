import shake as sh
import socket

#
# trying to rewrite the handshake...
def test_my(cf):
  # Context creation
  sc = sh.MySSLContext()
  sc.vmm()
  shll = sh.MySSLSocket

  # Load the CA certificates used for validating the peer's certificate
  sc.load_verify_locations(cafile=cf)

  secSock = sc.my_wrap_socket(socket.socket())

  # Make the connection
  shll.my_connect(secSock, ("localhost", 4443))

  # Explicit handshake & Get the certificate of the server
  shll.my_do_handshake(secSock)
  return shll.my_getpeercert(secSock)

#
# Default easy handshake, for sanity
def test_default(cf):
  import ssl

  # Context creation
  sslContext = ssl.SSLContext()
  sslContext.verify_mode = ssl.CERT_REQUIRED

  # Load the CA certificates used for validating the peer's certificate
  sslContext.load_verify_locations(cafile=cf)

  # Create an SSLSocket
  secureClientSocket = sslContext.wrap_socket(socket.socket())

  # Make the connection
  secureClientSocket.connect(("localhost", 4443))

  # Explicit handshake & Get the certificate of the server
  secureClientSocket.do_handshake()
  return secureClientSocket.getpeercert()

#
# main
import certifi
import os

cf = os.path.relpath(certifi.where())
assert(test_default(cf) == test_my(cf))
print("OK!")
