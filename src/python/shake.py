"""
```
    |                                                     |                    .
 cli|                                                     |srv                 .
    |                                                     |                    .
                                                                               .
     _____________ [1] TCP HANDSHAKE _____________________                     .
                                                                               |
     ----- >>> --- [1.1] syn ------------------- >   ----v                     |
     v---- <   --- [1.2] syn ack --------------- <<< -----        handled by os|
     ----- >>> --- [1.3] ack ------------------- >   -----                     |
                              v                                                |
                                                                               .
     _____________ [2] TLS HANDSHAKE _____________________                     .
                                                                               .
     ----- >>> --- [2.1] client hi ------------- >   ----v                     .
     ----- <   --- [2.1] server hi ------------- <<< -----                     .
     v---- <   --- [2.2] verify server crt ----- <<< -----                     .
     ----- >>> --- [2.3] client crt ------------ >   -----                     .
     ----- >>> --- [2.4] key exchange ---------- >   -----                     .
     ----- >>> --- [2.5] change cipher spec ---- >   -----                     .
     ----- >>> --- [2.6] client finish --------- >   ----v                     .
     ----- <   --- [2.7] change cipher spec ---- <<< -----                     .
     v---- <   --- [2.8] server finished ------- <<< -----                     .
     =-=-= >>> -=- [2.9] encrypted traffic -=-=- <<< -=-=-                     .
                                                                               .
     ...                                                                       .
     ...                                                                       .
     ...                                                                       .
     ...                                                                       .
```
[1] https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp
https://en.wikipedia.org/wiki/Handshaking#TCP_three-way_handshake

[2] https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:online-data-security/xcae6f4a7ff015e7d:secure-internet-protocols/a/transport-layer-security-protocol-tls
https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake

[2.1]
  prot ver : tls 1.3
  cipher suite : TLS_RSA_256_SHA
[2.2]
  prot ver : tls 1.3
  cipher suite : TLS_RSA_256_SHA
  cert : pubkey : 0x123456789abcdef
[2.3]
[2.4]
  cli send pre-master key,
  encrypted with servers public key 
  cli calculate shared key from pre-master
  store preshared key locally
[2.5]
[2.6]
  send "finish" encrypted with calculated share key
[2.7]
[2.8]
  server calculate shared key & try to decrypt clients "finish
  if successful, send back "finish" encrypted 
[2.9]
  cli send data using symmetric encryption and shared key
"""
# grabbed from https://raw.githubusercontent.com/python/cpython/main/Lib/ssl.py

import socket
from socket import SOL_SOCKET, SO_TYPE, SOCK_STREAM
from _ssl import _SSLContext

class sslc():
  def __new__(cls, protocol):
    from cffi import FFI
    ffi = FFI()

    ffi.set_source("_test", """
    #include <stdio.h>
    typedef struct Con {
      int x;
    } Con;

    Con* _SSLContext11(int *type, int prot_ver) {
      Con *s = NULL;
      (*s).x = 0;
      printf(\"hmm %d\\n\", (*s).x);
      return s;
    }

    int stuff(int protocol) {
      printf(\"stuff %d\\n\", protocol);
      //_SSLContext11(&protocol, protocol);
      return protocol*protocol;
    }

    long factorial(int n) {
        long r = n;
        while(n > 1) {
            n -= 1;
            r *= n;
        }
        return r;
    }
    """)
    ffi.cdef("""
    long factorial(int);
    int stuff(int protocol);
    //Con _SSLContext11(int *type, int prot_ver);
    """)
    # l = ffi.compile(tmpdir="/tmp")
    lib = ffi.dlopen(ffi.compile(tmpdir="/tmp"))
    print(lib.factorial(10))
    print(lib.stuff(protocol))
    #print(lib._SSLContext11(protocol, protocol))

class MySSLContext(_SSLContext):
  # An SSLContext holds various SSL-related configuration options and
  # data, such as certificates and possibly a private key.
  sslsocket_class = None  # SSLSocket is assigned later.

  def __new__(cls, protocol=None, *args, **kwargs):
    import ssl

    if protocol is None: protocol = 5 # ssl.PROTOCOL_TLSv1_2 = 5
    self = _SSLContext.__new__(cls, protocol)
    x = sslc.__new__(cls, protocol)
    return self

  def my_wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True,
    suppress_ragged_eofs=True, server_hostname=None, session=None):
    return MySSLSocket._create(s=sock,server_side=server_side,
      do_handshake_on_connect=do_handshake_on_connect,
      suppress_ragged_eofs=suppress_ragged_eofs, server_hostname=server_hostname,
      context=self, session=session)

  def wrap_bio(self, incoming, outgoing, server_side=False,
    server_hostname=None, session=None):
    # Need to encode server_hostname here because _wrap_bio() can only
    # handle ASCII str.
    return MySSLObject._create(incoming, outgoing, server_side=server_side,
      server_hostname=server_hostname, session=session)

  # ssl.VerifyMode : ssl.CERT_REQUIRED = 2
  def vmm(self): super(MySSLContext, MySSLContext).verify_mode.__set__(self, 2)

class MySSLObject:
  def __init__(self, *args, **kwargs):
    # Instances are returned by SSLContext.wrap_bio().
    raise TypeError(f"{self.__class__.__name__} no public construct")

  @classmethod
  def _create(cls, incoming, outgoing, server_side=False, server_hostname=None,
    session=None, context=None):
    self = cls.__new__(cls)
    sslobj = context._wrap_bio( incoming, outgoing, server_side=server_side,
      server_hostname=server_hostname, owner=self, session=session)
    self._sslobj = sslobj
    return self

  # Start the SSL/TLS handshake
  def do_handshake(self): self._sslobj.do_handshake()

  # Returns a formatted version of the data in the cert from ssl channel
  def getpeercert(self, binary_form=False): return self._sslobj.getpeercert(binary_form)


class MySSLSocket(socket.socket):
  # This class implements a subtype of socket.socket that wraps
  # the underlying OS socket in an SSL context when necessary, and
  # provides read and write methods over that channel.

  def __init__(self, *args, **kwargs):
    # Instances are returned by SSLContext.wrap_socket()
    raise TypeError(f"{self.__class__.__name__} no public construct")

  # Connects to remote ADDR, and then wraps the connection in an SSL channel.
  def my_connect(self, addr): self._real_connect(addr, False)

  # Connects to remote ADDR, and then wraps the connection in an SSL channel.
  def my_connect_ex(self, addr): return self._real_connect(addr, True)

  def my_getpeercert(self, binary_form=False):
    if not self._connected: self.getpeername()
    return self._sslobj.getpeercert(binary_form)

  def my_do_handshake(self, block=False):
    if not self._connected: self.getpeername()
    timeout = self.gettimeout()
    try:
      if timeout == 0.0 and block: self.settimeout(None)
      self._sslobj.do_handshake()
    finally: self.settimeout(timeout)

  def _real_connect(self, addr, connect_ex):
    # Here we assume that the socket is client-side, and not
    # connected at the time of the call.  We connect it, then wrap it.
    if self.server_side: raise ValueError("can't connect in server-side mode")
    if self._connected or self._sslobj is not None:
      raise ValueError("attempt to connect already-connected SSLSocket!")
    self._sslobj = self.context._wrap_socket(
      self, False, self.server_hostname, owner=self, session=self._session)
    try:
      rc = None
      if connect_ex: rc = self.connect_ex(addr)
      else: self.connect(addr)
      if not rc: self._connected = True
      return rc
    except (OSError, ValueError):
      self._sslobj = None
      raise

  @classmethod
  def _create(cls, s, server_side=False, do_handshake_on_connect=True,
    suppress_ragged_eofs=True, server_hostname=None, context=None, session=None):
    if s.getsockopt(SOL_SOCKET, SO_TYPE) != SOCK_STREAM:
      raise NotImplementedError("only stream sockets are supported")
    if server_side:
      if server_hostname: raise ValueError("server_hostname can set cli mode")
      if session is not None: raise ValueError("session can set cli mode")
    if context.check_hostname and not server_hostname:
      raise ValueError("check_hostname requires server_hostname")

    kwargs = dict(family=s.family, type=s.type, proto=s.proto,fileno=s.fileno())
    self = cls.__new__(cls, **kwargs)
    super(MySSLSocket, self).__init__(**kwargs)
    self.settimeout(s.gettimeout())
    s.detach()

    self._context = context
    self._session = session
    self._closed = False
    self._sslobj = None
    self.server_side = server_side
    self.server_hostname = server_hostname
    self.do_handshake_on_connect = do_handshake_on_connect
    self.suppress_ragged_eofs = suppress_ragged_eofs

    # See if we are connected, errno.ENOTCONN = 57
    try: self.getpeername()
    except OSError as e:
      if e.errno != 57: raise
      connected = False
    else: connected = True

    self._connected = connected
    if connected: # create the SSL object
      try:
        self._sslobj = self._context._wrap_socket(self, server_side,
          self.server_hostname,owner=self, session=self._session,)
        if do_handshake_on_connect:
          # do_handshake_on_connect should't be spec for non-blocking sockets
          if self.gettimeout() == 0.0: raise ValueError("shouldn't be set")
          self.do_handshake()
      except (OSError, ValueError):
        self.close()
        raise
    return self

  @property
  def context(self): return self._context

  @context.setter
  def context(self, ctx):
    self._context = ctx
    self._sslobj.context = ctx

MySSLContext.sslsocket_class = MySSLSocket

