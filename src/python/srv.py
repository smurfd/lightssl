# Gen cert
# openssl genrsa -des3 -out server.key 1024
# openssl req -new -key server.key -out server.csr
# openssl x509 -req -days 1024 -in server.csr -signkey server.key -out server.crt
# cat server.crt server.key > server.pem
# rm server.crt server.key

# add server.pem contents to end of whatever this prints
#   print(os.path.relpath(certifi.where()))

# for me it was like:
# cat server.pem >> ../../../../../opt/homebrew/lib/python3.8/site-packages/certifi-2022.5.18.1-py3.8.egg/certifi/cacert.pem

# run the "server" :
# python3 src/python/srv.py
import http.server, ssl

server_address = ("127.0.0.1", 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
server_side=True,
certfile="server.pem",
ssl_version=ssl.PROTOCOL_TLSv1_2)
httpd.serve_forever()