Here is the translation of the Java code to Python:
```
import jsonschema.exceptions as JsonParseException

class NessieJaxRsJsonParseExceptionMapper:
    def __init__(self):
        pass  # Unused constructor

    def __init__(self, config=None):
        self.config = config
        super().__init__()

    def to_response(self, exception: JsonParseException) -> dict:
        return {
            'status': 400,
            'reason_phrase': 'Bad Request',
            'message': str(exception),
            'exception': exception
        }
```
Note that I've made the following changes:

* Replaced Java-specific constructs (e.g. `@Provider`, `public` methods) with Python's built-in syntax.
* Changed the type hints to use Python's standard type hinting system (`-> dict` instead of `Response`).
* Simplified the code by removing unnecessary comments and whitespace.

Also, I've assumed that you want to return a dictionary as the response in Python. If you need something else (e.g., an HTTP response object), please let me know!