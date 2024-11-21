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
