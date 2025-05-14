'''
SOURCE: [ Ajeeb.K.P ]
https://askubuntu.com/questions/1405271/how-do-i-enable-cors-for-a-local-python3-http-server
'''
from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys


class CORSRequestHandler(SimpleHTTPRequestHandler):
    
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        '''
        added `no-referrer` to overcome -
        "Failed to load resource: net::ERR_CONNECTION_REFUSED" in Chromium v79.0.3945.0
        '''
        self.send_header('Referrer-Policy', 'no-referrer')
        
        return super(CORSRequestHandler, self).end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

host = sys.argv[1] if len(sys.argv) > 2 else '0.0.0.0'
port = int(sys.argv[len(sys.argv)-1]) if len(sys.argv) > 1 else 8080

print("Listening on {}:{}".format(host, port))
httpd = HTTPServer((host, port), CORSRequestHandler)
httpd.serve_forever()
