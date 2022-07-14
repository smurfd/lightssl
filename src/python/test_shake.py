import platform
import certifi
import socket
import os
import shake as sh

#
# trying to rewrite the handshake...
def test_my():
  # Context creation
  sc = sh.MySSLContext()
  sc.vmm()
  shll = sh.MySSLSocket

  # Load the CA certificates used for validating the peer's certificate
  sc.load_verify_locations(cafile=os.path.relpath(certifi.where()))

  secSock = sc.wrap_socket(socket.socket())

  # Make the connection
  shll.connect1(secSock, ("localhost", 4443))

  # Explicit handshake & Get the certificate of the server
  shll.do_handshake1(secSock)
  return shll.getpeercert1(secSock)

#
# Default easy handshake, for sanity
def test_default():
  import ssl
  # Context creation
  sslContext = ssl.SSLContext()
  sslContext.verify_mode = ssl.CERT_REQUIRED

  # Load the CA certificates used for validating the peer's certificate
  sslContext.load_verify_locations(cafile=os.path.relpath(certifi.where()))

  # Create an SSLSocket
  secureClientSocket = sslContext.wrap_socket(socket.socket())

  # Make the connection
  secureClientSocket.connect(("localhost", 4443))

  # Explicit handshake & Get the certificate of the server
  secureClientSocket.do_handshake()
  return secureClientSocket.getpeercert()

#
# main
assert(test_default() == test_my())
print("OK!")
