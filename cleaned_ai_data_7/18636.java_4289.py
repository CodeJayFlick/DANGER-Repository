from http.server import HTTPServer, BaseHTTPRequestHandler

class UnauthenticatedFilter:
    HEADER_NAME = "X-Unauthenticated-Response"
    RESPONSE_STATUS = 401

    def do_filter(self, servlet_request: dict, servlet_response: dict):
        if 'HTTP_X_UNAUTHENTICATED_RESPONSE' in servlet_request.get('headers', {}):
            servlet_response['status'] = self.RESPONSE_STATUS
            return

        # Call the next filter or start responding to the request.
        pass


class EchoRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if 'HTTP_X_UNAUTHENTICATED_RESPONSE' in self.headers:
            self.send_response(UnauthenticatedFilter.RESPONSE_STATUS)
            return

        self.send_response(200, "Hello from Python!")
        self.end_headers()
        with open('echo.txt', 'w') as f:
            f.write(self.rfile.read(int(self.headers['Content-Length'])))
        self.wfile.write(b"Hello from Python!")


def run_server():
    server_address = ('127.0.0.1', 8000)
    httpd = HTTPServer(server_address, EchoRequestHandler)

    print("Starting Server...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run_server()
