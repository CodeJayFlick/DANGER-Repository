import logging
from rest_framework.response import Response
from rest_framework.status import HTTP_500_INTERNAL_SERVER_ERROR, \
    HTTP_BAD_REQUEST, HTTP_TOO_MANY_REQUESTS, HTTP_FORBIDDEN

class NessieExceptionMapper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def to_response(self, exception: Exception) -> Response:
        status_code = None
        reason_phrase = None
        message = None

        if isinstance(exception, WebApplicationException):
            response = exception.response
            status_code = response.status_code
            reason_phrase = response.reason
            message = str(exception)

        elif isinstance(exception, BaseNessieClientServerException):
            status_code = exception.status
            reason_phrase = exception.reason
            message = str(exception)

        elif (isinstance(exception, JsonParseException) or 
              isinstance(exception, JsonMappingException) or 
              isinstance(exception, IllegalArgumentException)):
            status_code = HTTP_BAD_REQUEST
            reason_phrase = "Bad Request"
            message = str(exception)

        elif isinstance(exception, BackendLimitExceededException):
            self.logger.warning("Backend throttled/refused the request: %s", exception)
            status_code = HTTP_TOO_MANY_REQUESTS
            reason_phrase = "Too Many Requests"
            message = f"Backend store refused to process the request: {exception}"

        elif isinstance(exception, AccessControlException):
            status_code = HTTP_FORBIDDEN
            reason_phrase = "Forbidden"
            message = str(exception)

        else:
            self.logger.warning("Unhandled exception returned as HTTP/500 to client", exception)
            status_code = HTTP_500_INTERNAL_SERVER_ERROR
            reason_phrase = "Internal Server Error"
            message = ", ".join(map(str, Throwables.get_causal_chain(exception)))

        return Response({"status": status_code, "reason": reason_phrase, "message": message}, 
                        status=status_code)

class WebApplicationException(Exception):
    def __init__(self, response: dict):
        self.response = response

def build_exception_response(status_code: int, reason_phrase: str, message: str, exception: Exception) -> Response:
    return None  # This method is not implemented in the original Java code
