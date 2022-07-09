import platform
import certifi
import socket
import ssl
import os

def ssl_real_connect(sock, ssock, addr, connect_ex):
  if ssock.server_side:
    raise ValueError("can't connect in server-side mode")
  # Here we assume that the socket is client-side, and not
  # connected at the time of the call.  We connect it, then wrap it.
  if ssock._connected or ssock._sslobj is not None:
    raise ValueError("attempt to connect already-connected SSLSocket!")

  ssock._sslobj = ssock.context._wrap_socket(sock, False, ssock.server_hostname,
    owner=ssock, session=ssock._session)
  try:
    if connect_ex: rc = sock.connect_ex(addr)
    else:
      rc = None
      sock.connect(addr)
      if not rc: ssock._connected = True
      if ssock.do_handshake_on_connect:
        ssock.do_handshake()
        return rc
  except (OSError, ValueError):
    ssock._sslobj = None
    raise

def ssl_connect(sock, ssock, addr):
  """Connects to remote ADDR, and then wraps the connection in
  an SSL channel."""
  ssl_real_connect(sock, ssock, addr, False)

def ssl_sock_chk_conn(ssock):
  if not ssock._connected:
    ssock.getpeername()

def ssl_getpeercert(ssock, binary_form=False):
  ssl_sock_chk_conn(ssock)
  return ssock._sslobj.getpeercert(binary_form)

def ssl_sock_do_shake(ssock, block=False):
  ssl_sock_chk_conn(ssock)
  ssock._sslobj.do_handshake()

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
  secureClientSocket = sslContext.wrap_socket(
    socket.socket(), do_handshake_on_connect=False)

  # Make the connection
  ssl_connect(ss, secureClientSocket, ("example.org", 443))

  # Explicit handshake
  ssl_sock_do_shake(secureClientSocket)

  # Get the certificate of the server
  assert(ssl_getpeercert(secureClientSocket))

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
