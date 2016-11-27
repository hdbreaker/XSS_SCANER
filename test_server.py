#!/usr/bin/env python
import time
import urllib
import BaseHTTPServer


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """Respond to a GET request."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("<html><head><title>Title goes here.</title></head>")
        self.wfile.write(
            "<body><form action='.' method='GET'><input name='test' value='' /><input type='submit' /></form><p>This is a test.</p>")
        self.wfile.write("<p>GET: You accessed path: " +
                         urllib.unquote(self.path) + "</p>")
        self.wfile.write("</body></html>")

    def log_message(self, format, *args):
        return

server_class = BaseHTTPServer.HTTPServer
try:
    httpd = server_class(("localhost", 9669), Handler)
    print time.asctime(), "Server Starts - %s:%s" % ("localhost", 9669)
    httpd.serve_forever()
except:
    print "[#] Something is running on localhost:9669 checking for alive instance of testing server"
