from http.server import HTTPServer, BaseHTTPRequestHandler

class UnauthenticatedFilter(BaseHTTPRequestHandler):
    HEADER_NAME = "X-Unauthenticated-Response"
    RESPONSE_STATUS = 401

    def do_GET(self):
        if self.headers.get(HEADER_NAME) is not None:
            self.send_response(UnauthenticatedFilter.RESPONSE_STATUS)
            return
        self.server_version + ' Python/' + sys.version + '\r\n'
        self.end_headers()
        # Your code to handle the request goes here

    def finish(self):
        pass  # No need for this in our case, but it's required by BaseHTTPRequestHandler


def run(server_class=HTTPServer, handler_class=UnauthenticatedFilter):
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    print("Starting httpd...")
    httpd.serve_forever()


if __name__ == "__main__":
    from sys import argv
    run()
