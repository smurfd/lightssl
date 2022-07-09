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
