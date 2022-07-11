# grabbed from https://raw.githubusercontent.com/python/cpython/main/Lib/ssl.py

"""
TODO:
_create()
._wrap_bio()
._wrap_socket()
._sslobj

"""

from socket import SOL_SOCKET, SO_TYPE, SOCK_STREAM
import socket
import ssl

#sslcontext
def ssl_wrap_socket(s, sock, server_side=False, do_handshake_on_connect=True,
  suppress_ragged_eofs=True, server_hostname=None, session=None):
  # SSLSocket class handles server_hostname encoding before it calls
  # ctx._wrap_socket()

#  return ssl_create(s.sslsocket_class, sock=sock, server_side=server_side,
#    do_handshake_on_connect=do_handshake_on_connect,
#    suppress_ragged_eofs=suppress_ragged_eofs, server_hostname=server_hostname,
#    context=s, session=session)
  return s.sslsocket_class._create(sock=sock, server_side=server_side,
    do_handshake_on_connect=do_handshake_on_connect,
    suppress_ragged_eofs=suppress_ragged_eofs, server_hostname=server_hostname,
    context=s, session=session)

def ssl_wrap_bio(s, incoming, outgoing, server_side=False,
  server_hostname=None, session=None):
  # Need to encode server_hostname here because _wrap_bio() can only
  # handle ASCII str.
  return ssl1_create(s.sslobject_class, incoming, outgoing,
    server_side=server_side, server_hostname=s._encode_hostname(
    server_hostname), session=session, context=s,)
#  return s.sslobject_class._create( incoming, outgoing,
#    server_side=server_side, server_hostname=s._encode_hostname(
#    server_hostname), session=session, context=s,)

# sslobject
def ssl_create(s, incoming, outgoing, server_side=False, server_hostname=None,
  session=None, context=None):
    #s = cls.__new__(cls)
    #s = __new__(SSLObject)
  sslobj = ssl_wrap_bio(context, incoming, outgoing, server_side=server_side,
    server_hostname=server_hostname, owner=s, session=session)

#  sslobj = context._wrap_bio(incoming, outgoing, server_side=server_side,
#    server_hostname=server_hostname, owner=s, session=session)
  s._sslobj = sslobj
  return s

# sslsocket
def ssl_create(s, sock, server_side=False, do_handshake_on_connect=True,
  suppress_ragged_eofs=True, server_hostname=None, context=None, session=None):
  if sock.getsockopt(SOL_SOCKET, SO_TYPE) != SOCK_STREAM:
    raise NotImplementedError("only stream sockets are supported")
  if server_side:
    if server_hostname:
      raise ValueError("server_hostname can only be specified in client mode")
    if session is not None:
      raise ValueError("session can only be specified in client mode")
  if context.check_hostname and not server_hostname:
    raise ValueError("check_hostname requires server_hostname")

  kwargs = dict(family=sock.family, type=sock.type, proto=sock.proto,
      fileno=sock.fileno())
  #s = cls.__new__(cls, **kwargs)
  #s = __new__(SSLSocket, **kwargs)
  socket.socket(s, type=sock.type).__init__(**kwargs)
  s.settimeout(sock.gettimeout())
  sock.detach()

  s._context = context
  s._session = session
  s._closed = False
  s._sslobj = None
  s.server_side = server_side
  s.server_hostname = context._encode_hostname(server_hostname)
  s.do_handshake_on_connect = do_handshake_on_connect
  s.suppress_ragged_eofs = suppress_ragged_eofs

    # See if we are connected
  try:
      s.getpeername()
  except OSError as e:
      if e.errno != errno.ENOTCONN:
        raise
      connected = False
  else:
      connected = True

  s._connected = connected
  if connected:
      # create the SSL object
      try:
        s._sslobj = s._context._wrap_socket(s, server_side, s.server_hostname,
          owner=s, session=s._session,)
        if do_handshake_on_connect:
          timeout = s.gettimeout()
          if timeout == 0.0:
            # non-blocking
            raise ValueError("do_handshake_on_connect should not be specified",
              " for non-blocking sockets")
          s.do_handshake()
      except (OSError, ValueError):
        s.close()
        raise
  return s

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
        ssl_sock_do_shake(ssock)
        return rc
  except (OSError, ValueError):
    ssock._sslobj = None
    raise

# Connects to remote ADDR, and then wraps the connection in an SSL channel
def ssl_connect(sock, ssock, addr):
  ssl_real_connect(sock, ssock, addr, False)

# Connects to remote ADDR, and then wraps the connection in an SSL channel.
def ssl_connect_ex(sock, ssock, addr):
  return ssl_real_connect(sock, ssock, addr, True)

def ssl_sock_chk_conn(ssock):
  if not ssock._connected:
    ssock.getpeername()

def ssl_getpeercert(ssock, binary_form=False):
  ssl_sock_chk_conn(ssock)
  return ssock._sslobj.getpeercert(binary_form)

def ssl_sock_do_shake(ssock, block=False):
  ssl_sock_chk_conn(ssock)
  ssock._sslobj.do_handshake()
