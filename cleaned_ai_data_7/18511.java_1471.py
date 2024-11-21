import logging
from typing import Any

class AwsProxyExceptionHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    INTERNAL_SERVER_ERROR = "Internal Server Error"
    GATEWAY_TIMEOUT_ERROR = "Gateway timeout"

    _headers = {"Content-Type": "application/json"}

    def handle(self, ex: Exception) -> dict:
        self.logger.error("Called exception handler for:", exc_info=True)

        if isinstance(ex, (InvalidRequestEventException, InternalServerErrorException)):
            return {
                "statusCode": 500,
                "body": self.get_error_json(AwsProxyExceptionHandler.INTERNAL_SERVER_ERROR)
            }
        else:
            return {
                "statusCode": 502,
                "body": self.get_error_json(AwsProxyExceptionHandler.GATEWAY_TIMEOUT_ERROR)
            }

    def get_error_json(self, message: str) -> dict:
        try:
            error_model = {"message": message}
            return error_model
        except Exception as e:
            self.logger.error("Could not produce error JSON", exc_info=True)
            return {"message": message}

if __name__ == "__main__":
    handler = AwsProxyExceptionHandler()
