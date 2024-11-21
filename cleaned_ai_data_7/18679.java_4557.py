class Struts2LambdaHandler:
    def __init__(self):
        self.handler = Struts2LambdaContainerHandler.get_aws_proxy_handler()

    def handle_request(self, input_stream: bytes, output_stream: bytearray, context: dict) -> None:
        try:
            self.handler.proxy_stream(input_stream, output_stream, context)
        except Exception as e:
            print(f"Error handling request: {e}")
