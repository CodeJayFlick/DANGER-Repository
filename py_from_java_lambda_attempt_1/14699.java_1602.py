Here is the translation of the Java code to Python:
```
class SimpleMessage:
    def __init__(self):
        self.headers = {}
        self.body = None

    def add_header(self, header: str, value: str) -> None:
        self.headers[header] = value

    def get_header(self, header: str) -> str:
        return self.headers.get(header)

    def get_headers(self) -> dict:
        return self.headers.copy()

    def set_body(self, body: str) -> None:
        self.body = body

    def get_body(self) -> str:
        return self.body
```
Note that I've used Python's built-in `dict` type to represent the map of headers, and omitted the explicit import statements since they are not necessary in this case.