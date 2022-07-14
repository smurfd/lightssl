# grabbed from https://raw.githubusercontent.com/python/cpython/main/Lib/ssl.py

import socket
import errno
import ssl
from _ssl import _SSLContext
from socket import SOL_SOCKET, SO_TYPE, SOCK_STREAM

class MySSLContext(_SSLContext):
  """An SSLContext holds various SSL-related configuration options and
  data, such as certificates and possibly a private key."""
  sslsocket_class = None  # SSLSocket is assigned later.
  sslobject_class = None  # SSLObject is assigned later.

  def __new__(cls, protocol=None, *args, **kwargs):
    if protocol is None: protocol = ssl.PROTOCOL_TLSv1_2
    self = _SSLContext.__new__(cls, protocol)
    return self

  def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True,
    suppress_ragged_eofs=True, server_hostname=None, session=None):
    return MySSLSocket._create(sock=sock,server_side=server_side,
      do_handshake_on_connect=do_handshake_on_connect,
      suppress_ragged_eofs=suppress_ragged_eofs, server_hostname=server_hostname,
      context=self, session=session)

  def wrap_bio(self, incoming, outgoing, server_side=False,
    server_hostname=None, session=None):
    # Need to encode server_hostname here because _wrap_bio() can only
    # handle ASCII str.
    return MySSLObject._create(incoming, outgoing, server_side=server_side,
      server_hostname=self._encode_hostname(server_hostname), session=session,
      context=self,)

  def vmm(self):
    super(MySSLContext, MySSLContext).verify_mode.__set__(self, 2)
    # ssl.CERT_REQUIRED = 2

class MySSLObject:
  def __init__(self, *args, **kwargs):
    raise TypeError(f"{self.__class__.__name__} does not have a public "
      f"constructor. Instances are returned by SSLContext.wrap_bio().")

  @classmethod
  def _create(cls, incoming, outgoing, server_side=False, server_hostname=None,
    session=None, context=None):
    self = cls.__new__(cls)
    sslobj = context._wrap_bio( incoming, outgoing, server_side=server_side,
      server_hostname=server_hostname, owner=self, session=session)
    self._sslobj = sslobj
    return self

  def do_handshake(self):
    """Start the SSL/TLS handshake."""
    self._sslobj.do_handshake()

  def getpeercert(self, binary_form=False):
    """Returns a formatted version of the data in the certificate provided
    by the other end of the SSL channel.

    Return None if no certificate was provided, {} if a certificate was
    provided, but not validated."""
    return self._sslobj.getpeercert(binary_form)

class MySSLSocket(socket.socket):
  """This class implements a subtype of socket.socket that wraps
  the underlying OS socket in an SSL context when necessary, and
  provides read and write methods over that channel. """

  def __init__(self, *args, **kwargs):
    raise TypeError(f"{self.__class__.__name__} does not have a public "
      f"constructor. Instances are returned by SSLContext.wrap_socket().")

  def connect1(self, addr):
    # Connects to remote ADDR, and then wraps the connection in an SSL channel.
    print("my connect")
    self._real_connect(addr, False)

  def connect_ex1(self, addr):
    # Connects to remote ADDR, and then wraps the connection in an SSL channel.
    print("my connect ex")
    return self._real_connect(addr, True)

  def getpeercert1(self, binary_form=False):
    print("my getpeercert")
    if not self._connected: self.getpeername()
    return self._sslobj.getpeercert(binary_form)

  def do_handshake1(self, block=False):
    print("my do_handshake")
    if not self._connected: self.getpeername()
    timeout = self.gettimeout()
    try:
      if timeout == 0.0 and block: self.settimeout(None)
      self._sslobj.do_handshake()
    finally:
      self.settimeout(timeout)

  def _real_connect(self, addr, connect_ex):
    print("my real_connect")
    if self.server_side: raise ValueError("can't connect in server-side mode")
      # Here we assume that the socket is client-side, and not
      # connected at the time of the call.  We connect it, then wrap it.
    if self._connected or self._sslobj is not None:
      raise ValueError("attempt to connect already-connected SSLSocket!")
    self._sslobj = self.context._wrap_socket(
      self, False, self.server_hostname, owner=self, session=self._session)
    try:
      if connect_ex: rc = self.connect_ex(addr)
      else:
        rc = None
        self.connect(addr)
      if not rc:
        self._connected = True
      return rc
    except (OSError, ValueError):
      self._sslobj = None
      raise

  @classmethod
  def _create(cls, sock, server_side=False, do_handshake_on_connect=True,
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
    self = cls.__new__(cls, **kwargs)
    super(MySSLSocket, self).__init__(**kwargs)
    self.settimeout(sock.gettimeout())
    sock.detach()

    self._context = context
    self._session = session
    self._closed = False
    self._sslobj = None
    self.server_side = server_side
    self.server_hostname = server_hostname
    self.do_handshake_on_connect = do_handshake_on_connect
    self.suppress_ragged_eofs = suppress_ragged_eofs

    # See if we are connected
    try:
      self.getpeername()
    except OSError as e:
      if e.errno != errno.ENOTCONN:
        raise
      connected = False
    else:
      connected = True

    self._connected = connected
    if connected:
      # create the SSL object
      try:
        self._sslobj = self._context._wrap_socket(
          self, server_side, self.server_hostname,
          owner=self, session=self._session,)
        if do_handshake_on_connect:
          timeout = self.gettimeout()
          if timeout == 0.0:
            # non-blocking
            raise ValueError("do_handshake_on_connect should not be specified"
              " for non-blocking sockets")
          self.do_handshake()
      except (OSError, ValueError):
        self.close()
        raise
    return self

  @property
  def context(self):
    return self._context

  @context.setter
  def context(self, ctx):
    self._context = ctx
    self._sslobj.context = ctx

MySSLContext.sslsocket_class = MySSLSocket