import socket
import ssl
import platform
import time

# Context creation
sslContext = ssl.SSLContext();
sslContext.verify_mode = ssl.CERT_REQUIRED;

# Check for OS X platform
if platform.system().lower() == 'darwin':
  import certifi
  import os
  print("cafile = ",os.path.relpath(certifi.where()))
  # Load the CA certificates used for validating the peer's certificate
  sslContext.load_verify_locations(cafile=os.path.relpath(certifi.where()),
    capath=None,cadata=None);

# Create an SSLSocket
clientSocket = socket.socket();
secureClientSocket = sslContext.wrap_socket(clientSocket, do_handshake_on_connect=False);

# Only connect, no handshake
t1 = time.time();
retval = secureClientSocket.connect(("example.org", 443));
print("Time taken to establish the connection:%2.3f"%(time.time() - t1));

# Explicit handshake
t3 = time.time();
secureClientSocket.do_handshake();
print("Time taken for SSL handshake:%2.3f"%(time.time() - t3));

# Get the certificate of the server and print
serverCertificate = secureClientSocket.getpeercert();
print("Certificate obtained from the server:");
print(serverCertificate);
