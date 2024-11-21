import boto3

class StreamLambdaHandler:
    def __init__(self):
        self.handler = None

    def initialize_handler(self):
        try:
            self.handler = SpringLambdaContainerHandler(SpringApiConfig())
        except ContainerInitializationException as e:
            print("Could not initialize Spring framework", file=sys.stderr)
            raise RuntimeError(str(e))

    @staticmethod
    def get_handler():
        if StreamLambdaHandler().handler is None:
            StreamLambdaHandler().initialize_handler()
        return StreamLambdaHandler().handler

    def handle_request(self, inputStream, outputStream, context):
        self.get_handler().proxy_stream(inputStream, outputStream, context)

# Note: This code assumes you have a SpringApiConfig class defined elsewhere
