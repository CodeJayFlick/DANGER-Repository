import requests
from urllib.parse import urlparse, urljoin
from io import BytesIO
from typing import IO

class HttpSymbolServer:
    GHIDRA_USER_AGENT = "Ghidra_HttpSymbolServer_client"
    HTTP_STATUS_OK = 200
    REQUEST_TIMEOUT_MS = 10000  # 10 seconds

    def __init__(self, server_uri: str):
        self.server_uri = urlparse(server_uri)
        if not self.server_uri.path.endswith('/'):
            self.server_uri = (urljoin(self.server_uri.geturl(), '/'),)

    @property
    def name(self) -> str:
        return self.server_uri.geturl()

    def is_valid(self, monitor=None):
        try:
            response = requests.head(urljoin(self.server_uri.geturl(), self.name), timeout=self.REQUEST_TIMEOUT_MS/1000)
            if response.status_code == self.HTTP_STATUS_OK:
                return True
        except (requests.exceptions.RequestException, ConnectionResetError) as e:
            print(f"Failed to check the symbol server: {e}")
        return False

    def exists(self, filename: str):
        try:
            request = requests.head(urljoin(self.server_uri.geturl(), filename), timeout=self.REQUEST_TIMEOUT_MS/1000)
            if request.status_code == self.HTTP_STATUS_OK:
                return True
        except (requests.exceptions.RequestException, ConnectionResetError) as e:
            print(f"Failed to check the existence of {filename}: {e}")
        return False

    def get_file_stream(self, filename: str):
        try:
            response = requests.get(urljoin(self.server_uri.geturl(), filename), timeout=self.REQUEST_TIMEOUT_MS/1000)
            if response.status_code == self.HTTP_STATUS_OK:
                content_len = int(response.headers['Content-Length'])
                return BytesIO(response.content) if content_len > 0 else None
        except (requests.exceptions.RequestException, ConnectionResetError) as e:
            print(f"Failed to get the file {filename}: {e}")
        return None

    def get_file_location(self, filename: str):
        return urljoin(self.server_uri.geturl(), filename)

    @property
    def is_local(self) -> bool:
        return False

    def __str__(self):
        return f"HttpSymbolServer: [url: {self.name}, storageLevel: ?]"

if __name__ == "__main__":
    server = HttpSymbolServer("http://example.com")
    print(server.is_valid())
