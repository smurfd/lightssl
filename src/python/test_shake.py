import platform
import certifi
import socket
import ssl
import os
from shake import *

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

  # Create an SSLSocket
  ss = socket.socket() # not sure why i cant use this as arg to wrap_socket()
  secureClientSocket = ssl_wrap_socket(sslContext,
    socket.socket(), do_handshake_on_connect=False)
#  secureClientSocket = sslContext.wrap_socket(
#    socket.socket(), do_handshake_on_connect=False)

  # Make the connection
  ssl_connect(ss, secureClientSocket, ("example.org", 443))

  # Explicit handshake
  ssl_sock_do_shake(secureClientSocket)

  # Get the certificate of the server
  assert(ssl_getpeercert(secureClientSocket))
  secureClientSocket.close()
  ss.close()

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
