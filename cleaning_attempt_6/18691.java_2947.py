import logging

class SpringApiConfig:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    # Create required HandlerMapping
    def handler_mapping(self):
        return {'handler_mapping': 'RequestMappingHandlerMapping'}

    # Create required HandlerAdapter
    def handler_adapter(self):
        return {'handler_adapter': 'RequestMappingHandlerAdapter'}

    # optimization - avoids creating default exception resolvers; not required as the serverless container handles all exceptions
    def handler_exception_resolver(self):
        class CustomResolver:
            def resolve_exception(self, request, response, handler, ex):
                self.logger.info(f"Exception occurred: {ex}")
                return None

        return {'handler_exception_resolver': CustomResolver()}

# Create an instance of SpringApiConfig and call its methods
config = SpringApiConfig()
print(config.handler_mapping())
print(config.handler_adapter())
print(config.handler_exception_resolver())
