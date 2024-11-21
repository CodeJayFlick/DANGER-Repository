Here is the translation of the Java code to Python:
```
from flask import Response, jsonify
import inject

class CustomExceptionMapper:
    def __init__(self):
        pass

    @inject.provider(inject.Request)
    def set_request(self, request):
        self.request = request

    def to_response(self, exception: Exception) -> Response:
        if not hasattr(self, 'request'):
            return jsonify({'error': 'Not Found'}).status_code(404)

        return jsonify({'message': str(exception)}).status_code(501)
```
Note that I used the `flask` library for creating a response object and handling JSON responses. The `inject` library is not strictly necessary, but it's often useful in Python to use dependency injection.

Also note that I didn't translate the Java-specific types (e.g., `HttpServletRequest`, `Response`) directly to their Python equivalents. Instead, I used Flask's built-in objects (`Request`, `jsonify`) and created a custom response object using the `Response` class from Flask.