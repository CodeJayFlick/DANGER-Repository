class ExceptionHandler:
    def __init__(self):
        pass

    def handle(self, ex: Exception) -> any:
        # implement your exception handling logic here
        raise NotImplementedError("Implement this method")

    def stream_handle(self, ex: Exception, output_stream: bytes) -> None:
        try:
            # implement your exception handling logic for the stream-based proxy
            pass  # todo: handle the exception and write to the output stream
        except Exception as e:
            raise IOException(f"Exception handler failed to write to the OutputStream") from e

