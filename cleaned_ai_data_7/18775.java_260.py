import urllib.parse
from typing import Dict, List, Optional

class RequestContext:
    def __init__(self, headers: Dict[str, set], uri: str, method: str, body=None):
        self.headers = headers
        self.uri = urllib.parse.urlunparse(urllib.parse.urlparse(uri))
        self.method = method
        self.body = body

    @property
    def get_headers(self) -> Dict[str, set]:
        return self.headers

    def put_header(self, name: str, value: str):
        # Note: This is a translation of the Java code, but it's not clear what HttpRequest.putHeader does.
        pass

    @property
    def get_uri(self) -> str:
        return self.uri

    @property
    def get_method(self) -> str:
        return self.method

    @property
    def get_body(self) -> Optional[object]:
        if self.body is None:
            return None
        else:
            return self.body

    def add_response_callback(self, response_callback: callable):
        if not hasattr(self, 'response_callbacks'):
            self.response_callbacks = []
        self.response_callbacks.append(response_callback)

    @property
    def get_response_callbacks(self) -> List[callable]:
        return self.response_callbacks
