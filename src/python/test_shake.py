import platform
import certifi
import socket
import ssl
import os
import shake as sh

#
#
# trying to rewrite the handshake...
def test_my():
  # Context creation
  sslContext = ssl.SSLContext()
  sslContext.verify_mode = ssl.CERT_REQUIRED

  # Load the CA certificates used for validating the peer's certificate
  sslContext.load_verify_locations(cafile=os.path.relpath(certifi.where()),
    capath=None,cadata=None)

  s = socket.socket()
  secureClientSocket = sslContext.wrap_socket(
    s, do_handshake_on_connect=False)

  # Make the connection
  assert(sh.SSLSocket1.connect1(secureClientSocket, ("example.org", 443)) == None)

  # Explicit handshake
  sh.SSLSocket1.do_handshake1(secureClientSocket)

  assert(sh.SSLSocket1.getpeercert1(secureClientSocket))

  secureClientSocket.close()
  socket.socket().close()


#
#
# Default easy handshake, for sanity
def test_default():
  # Context creation
  sslContext = ssl.SSLContext()
  sslContext.verify_mode = ssl.CERT_REQUIRED

  # Load the CA certificates used for validating the peer's certificate
  sslContext.load_verify_locations(cafile=os.path.relpath(certifi.where()),
    capath=None,cadata=None)

  # Create an SSLSocket
  secureClientSocket = sslContext.wrap_socket(
    socket.socket(), do_handshake_on_connect=False)

  # Make the connection
  assert(secureClientSocket.connect(("example.org", 443)) == None)

  # Explicit handshake
  secureClientSocket.do_handshake()

  # Get the certificate of the server
  assert(secureClientSocket.getpeercert())

  secureClientSocket.close()
  socket.socket().close()

#
#
# main
print("testing default...")
test_default()

print("testing my...")
test_my()
