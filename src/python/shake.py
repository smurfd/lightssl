import platform
import certifi
import socket
import ssl
import os

def ssl_sock_chk_conn(s):
  s.getpeername()

def ssl_getpeercert(s, binary_form=False):
  ssl_sock_chk_conn(s)
  return s._sslobj.getpeercert(binary_form)

def ssl_sock_do_shake(s, block=False):
  ssl_sock_chk_conn(s)
  s._sslobj.do_handshake()

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
ssl_sock_do_shake(secureClientSocket)

# Get the certificate of the server
assert(ssl_getpeercert(secureClientSocket))
