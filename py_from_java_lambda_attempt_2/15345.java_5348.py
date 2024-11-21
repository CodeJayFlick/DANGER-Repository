Here is the translation of the Java code to Python:
```python
import requests
import json
from urllib.parse import urlparse, urlunparse

class RequestNetworkController:
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"

    REQUEST_PARAM = 0
    REQUEST_BODY = 1

    SOCKET_TIMEOUT = 15000
    READ_TIMEOUT = 25000

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RequestNetworkController, cls).__new__(cls)
            # equivalent to Java's singleton pattern
            return cls._instance
        else:
            return cls._instance

    @property
    def client(self):
        if self._client is None:
            try:
                trust_all_certs = [X509TrustManager()]
                ssl_context = SSLContext()
                ssl_context.load_verify_locations(None, None)
                ssl_context.set_default_trust_algorithm("TLS")
                ssl_socket_factory = ssl_context.socket_factory
                builder = requests.Session().build()
                builder.trust_all_certificates(trust_all_certs[0])
                builder.ssl_version(ssl_context.SSLContext())
                self._client = builder.build()
            except Exception as e:
                pass  # ignore exceptions for now

        return self._client

    def execute(self, request_network, method, url, tag, request_listener):
        headers = Headers()

        if request_network.get_headers():
            for key, value in request_network.get_headers().items():
                headers.add(key, str(value))

        try:
            req_builder = requests.Request()
            http_url = urlparse(url)

            if request_network.get_request_type() == self.REQUEST_PARAM:
                if method.lower() == "get":
                    query_params = {}
                    for key, value in request_network.get_params().items():
                        query_params[key] = str(value)
                    url_parts = list(http_url.parts)
                    url_parts[4] += "&" + "&".join(f"{key}={value}" for key, value in query_params.items())
                    http_url = urlparse(urlunparse((*http_url.parts[:3], *url_parts)))
                else:
                    form_body = requests.FormDict()
                    for key, value in request_network.get_params().items():
                        form_body.add(key, str(value))
                    req_builder.url(http_url)
                    if method.lower() == "post":
                        req_builder.method(method, json.dumps(form_body).encode("utf-8"))
            else:
                body = requests.RequestBody(json.dumps(request_network.get_params()))
                req_builder.url(url)
                if method.lower() == "get":
                    req_builder.method(method, None)
                else:
                    req_builder.method(method, body)

            response = self.client.send(req_builder.prepare(), timeout=(self.SOCKET_TIMEOUT / 1000.0, self.READ_TIMEOUT / 1000.0))

            request_listener.on_response(tag, response.text.strip())

        except Exception as e:
            request_listener.on_error_response(tag, str(e))
```
Note that I've used the `requests` library to implement the HTTP requests in Python. The code is not exact equivalent of Java's code but it should give you an idea how to translate it.

Also note that this code does not handle exceptions properly and may raise unexpected errors if something goes wrong during execution. You might want to add proper error handling depending on your use case.