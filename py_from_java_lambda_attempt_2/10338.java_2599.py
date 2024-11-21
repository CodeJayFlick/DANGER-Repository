Here is the translation of the Java code into Python:

```Python
import requests
from io import BytesIO
from typing import Optional

class HttpUtil:
    @staticmethod
    def get_content(http_url_string: str, http_request_properties: dict = None, allow_redirect: bool = False) -> Optional[requests.Response]:
        try:
            url = requests.get(http_url_string)
            if not allow_redirect and 300 <= url.status_code < 400:
                raise Exception(f"Redirected to {url.url}")
            return url
        except requests.exceptions.RequestException as e:
            raise IOException(str(e))

    @staticmethod
    def get_file(http_url_string: str, http_request_properties: dict = None, allow_redirect: bool = False, dest_file_path: str) -> Optional[str]:
        try:
            response = HttpUtil.get_content(http_url_string, http_request_properties, allow_redirect)
            with open(dest_file_path, 'wb') as f:
                for chunk in iter(lambda: response.raw.read(8192), b""):
                    if not chunk:
                        break
                    f.write(chunk)
            return response.headers.get('Content-Type')
        except Exception as e:
            raise IOException(str(e))

class IOException(Exception):
    pass

if __name__ == "__main__":
    # Example usage
    http_url_string = "https://example.com"
    httpRequestProperties = {"key": "value"}
    allow_redirect = True
    dest_file_path = "/path/to/dest/file.txt"

    try:
        content_type = HttpUtil.get_file(http_url_string, httpRequestProperties, allow_redirect, dest_file_path)
        print(f"Content-Type: {content_type}")
    except IOException as e:
        print(str(e))
```

Note that Python does not have an exact equivalent to Java's `HttpURLConnection` class. Instead, we use the popular `requests` library for making HTTP requests in this translation.