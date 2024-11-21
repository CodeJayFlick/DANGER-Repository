Here is the translation of the Java code to Python:
```
import logging

class Server:
    def __init__(self, host: str, port: int, id: int):
        self.host = host
        self.port = port
        self.id = id

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def id(self) -> int:
        return self._id

    def serve(self, request):
        logging.info("Server ID {} associated to host: {}, and port {}. Processed request with value {}".format(
            self.id, self.host, self.port, request.value))

# Example usage:
if __name__ == "__main__":
    server = Server("example.com", 8080, 1)
    request = {"value": "Hello World"}
    server.serve(request)
```
Note that I used the `logging` module instead of SLF4J, as it is a built-in Python logging library. Also, I did not include any imports for Lombok or Slf4j, since they are Java-specific libraries and do not have direct equivalents in Python.

In this translation:

* The constructor (`__init__`) takes three arguments: `host`, `port`, and `id`.
* The properties (`@property` decorators) allow you to access the instance variables as attributes.
* The `serve` method is similar to its Java counterpart, but uses string formatting instead of concatenation for logging.

Keep in mind that this translation assumes a basic understanding of Python syntax and semantics. If you have any specific questions or concerns about the code, feel free to ask!