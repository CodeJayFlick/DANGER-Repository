Here is the equivalent Python code for the given Java file:

```Python
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class MetricsServlet(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        metric_registry = {}  # Replace with your actual metric registry
        mapper = json.dumps(metric_registry)  # Replace with your actual object mapper
        self.wfile.write(mapper.encode('utf-8'))

    def do_POST(self):
        self.do_GET()

def create_metrics_servlet_handler(path, metric_registry, mapper):
    return HTTPServer(('localhost', 8000), MetricsServlet)

class StaticHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        with open('iotdb/ui/static/index.html') as f:
            self.wfile.write(f.read().encode('utf-8'))

def create_static_handler():
    return HTTPServer(('localhost', 8001), StaticHandler)

class JettyUtil:
    @staticmethod
    def get_jetty_server(handlers, port):
        server = None
        for handler in handlers:
            if isinstance(handler, BaseHTTPRequestHandler):
                server = (handler.port_num,)
                break

        return server

# Usage example:

if __name__ == "__main__":
    metric_registry = {}  # Replace with your actual metric registry
    mapper = json.dumps(metric_registry)  # Replace with your actual object mapper
    metrics_servlet_handler = create_metrics_servlet_handler('/json', metric_registry, mapper)
    static_handler = create_static_handler()
    
    JettyUtil.get_jetty_server([metrics_servlet_handler, static_handler], 8000)

```

Please note that this is a simplified translation and may not work exactly as the original Java code.