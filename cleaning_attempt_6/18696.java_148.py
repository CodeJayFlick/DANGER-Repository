import boto3
from botocore.exceptions import ContainerInitializationError

class StreamLambdaHandler:
    handler = None

    def __init__(self):
        try:
            self.handler = SpringBootLambdaContainerHandler.get_aws_proxy_handler(Application)
        except ContainerInitializationError as e:
            print("Could not initialize Spring Boot application", file=sys.stderr)
            raise RuntimeError(e)

    def handle_request(self, inputStream: bytes, outputStream: bytearray, context) -> None:
        if isinstance(inputStream, str):
            inputStream = inputStream.encode()
        self.handler.proxy_stream(inputStream, outputStream, context)


class Application:
    pass


if __name__ == "__main__":
    handler = StreamLambdaHandler()

    # Example usage
    input_stream = b"Hello, World!"
    output_stream = bytearray()
    context = {"key": "value"}
    try:
        handler.handle_request(input_stream, output_stream, context)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

