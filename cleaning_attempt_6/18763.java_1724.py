import json
from urllib.parse import urlparse
from ssl import SSLContext
from socket import getdefaulttimeout
from typing import List

class HttpClient:
    def __init__(self,
                 base_uri: str,
                 read_timeout_millis: int = 25000,
                 connection_timeout_millis: int = 5000):
        self.base_uri = urlparse(base_uri)
        self.read_timeout_millis = read_timeout_millis
        self.connection_timeout_millis = connection_timeout_millis

    def register_request_filter(self, filter_func) -> None:
        pass  # implement this method if needed

    def register_response_filter(self, filter_func) -> None:
        pass  # implement this method if needed

    def new_request(self):
        return HttpRequest(
            self.base_uri,
            read_timeout_millis=self.read_timeout_millis,
            connection_timeout_millis=self.connection_timeout_millis
        )


class HttpClientBuilder:
    def __init__(self):
        self.base_uri = None
        self.mapper = None
        self.ssl_context = SSLContext()
        self.read_timeout_millis = 25000
        self.connection_timeout_millis = 5000

    @property
    def base_uri(self) -> str:
        return self._base_uri

    @base_uri.setter
    def base_uri(self, value: str):
        self._base_uri = urlparse(value)

    @property
    def mapper(self) -> None:
        return self._mapper

    @mapper.setter
    def mapper(self, value: None):
        self._mapper = value

    @property
    def ssl_context(self) -> SSLContext:
        return self._ssl_context

    @ssl_context.setter
    def ssl_context(self, value: SSLContext):
        self._ssl_context = value

    @property
    def read_timeout_millis(self) -> int:
        return self._read_timeout_millis

    @read_timeout_millis.setter
    def read_timeout_millis(self, value: int):
        self._read_timeout_millis = value

    @property
    def connection_timeout_millis(self) -> int:
        return self._connection_timeout_millis

    @connection_timeout_millis.setter
    def connection_timeout_millis(self, value: int):
        self._connection_timeout_millis = value

    def build(self) -> HttpClient:
        if not self.base_uri:
            raise ValueError("Cannot construct Http client. Must have a non-None uri")
        return HttpClient(
            base_uri=self.base_uri.geturl(),
            read_timeout_millis=self.read_timeout_millis,
            connection_timeout_millis=self.connection_timeout_millis
        )


class HttpRequest:
    def __init__(self, 
                 base_uri: str, 
                 mapper=None, 
                 request_filters=None, 
                 response_filters=None, 
                 ssl_context=SSLContext(), 
                 read_timeout_millis=int(getdefaulttimeout()[0]*1000), 
                 connection_timeout_millis=int(getdefaulttimeout()[1]*1000)):
        self.base_uri = base_uri
        self.mapper = mapper
        self.request_filters = request_filters if request_filters else []
        self.response_filters = response_filters if response_filters else []
        self.ssl_context = ssl_context
        self.read_timeout_millis = read_timeout_millis
        self.connection_timeout_millis = connection_timeout_millis


class HttpClientException(Exception):
    pass

# Usage:
builder = HttpClientBuilder()
client = builder.set_base_uri("https://example.com").build()

request = client.new_request()  # create a new request object
