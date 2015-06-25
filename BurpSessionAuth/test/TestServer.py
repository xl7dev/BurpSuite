#!/usr/bin/python

import BaseHTTPServer
import CGIHTTPServer

server = BaseHTTPServer.HTTPServer
handler = CGIHTTPServer.CGIHTTPRequestHandler
handler.cgi_directories = ["/"]

httpd = BaseHTTPServer.HTTPServer(("", 8000), handler)
httpd.serve_forever()
