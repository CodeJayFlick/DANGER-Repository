Here is the translation of the Java code into Python:

```Python
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime as dt

class ExampleBean:
    def __init__(self):
        self.field1 = None
        self.field2 = 0
        self.field3 = None

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(data['field1'], data['field2'], dt.fromisoformat(data['field3']))

class TestRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        query_params = parse_qs(urlparse(self.path).query)

        if 'x' in query_params:
            self.send_response(200)
            self.end_headers()
            output = json.dumps({'output': f"Received GET request with x={query_params['x'][0]}"})
            self.wfile.write(output.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length'))
        post_body = self.rfile.read(content_length).decode()
        
        if 'output' in json.loads(post_body)['output']:
            output = f"Received POST request with x={json.loads(post_body)['x']}"
        else:
            output = "Invalid JSON"

        self.send_response(200)
        self.end_headers()
        self.wfile.write(output.encode())

    def do_PUT(self):
        if 'x' in parse_qs(urlparse(self.path).query):
            self.send_response(200)
            self.end_headers()
            output = f"Received PUT request with x={parse_qs(urlparse(self.path).query)['x'][0]}"
            self.wfile.write(output.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if 'x' in parse_qs(urlparse(self.path).query):
            self.send_response(200)
            self.end_headers()
            output = f"Received DELETE request with x={parse_qs(urlparse(self.path).query)['x'][0]}"
            self.wfile.write(output.encode())
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, TestRequestHandler)

    print("Starting server...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    run_server()
```

This Python code defines a simple web server that handles GET, POST, PUT and DELETE requests. The `ExampleBean` class is used to represent the JSON data sent in the request body or query parameters.

The `TestRequestHandler` class inherits from `BaseHTTPRequestHandle`, which provides methods for handling HTTP requests (GET, HEAD, POST, PUT, DELETE). In this code, we override these methods to handle specific types of requests.