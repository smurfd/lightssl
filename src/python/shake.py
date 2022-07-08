import platform
import certifi
import socket
import ssl
import os

# Context creation
sslContext = ssl.SSLContext()
sslContext.verify_mode = ssl.CERT_REQUIRED

# Load the CA certificates used for validating the peer's certificate
sslContext.load_verify_locations(cafile=os.path.relpath(certifi.where()),
  capath=None,cadata=None)

# Create an SSLSocket
secureClientSocket = sslContext.wrap_socket(
  socket.socket(), do_handshake_on_connect=False)

assert(secureClientSocket.connect(("example.org", 443)) == None)

# Explicit handshake
secureClientSocket.do_handshake()

# Get the certificate of the server
assert(secureClientSocket.getpeercert())
