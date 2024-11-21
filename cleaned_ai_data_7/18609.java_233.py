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
