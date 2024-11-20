Here is a translation of the Java code into equivalent Python:

```Python
import boto3
from botocore.exceptions import ContainerInitializationError
from enum import Enum

class DispatcherType(Enum):
    REQUEST = 1


def lambda_handler(event, context):
    try:
        handler = SpringLambdaContainerHandler(PetStoreSpringAppConfig)
        
        # we use the onStartup method of the handler to register our custom filter
        def startup(servlet_context):
            registration = servlet_context.add_filter("CognitoIdentityFilter", CognitoIdentityFilter())
            registration.add_mapping_for_url_patterns(DispatcherType.REQUEST, "/*")

        handler.on_startup(startup)

    except ContainerInitializationError as e:
        # if we fail here. We re-throw the exception to force another cold start
        print(f"Could not initialize Spring framework: {e}")
        raise

def enable_timer():
    Timer.enable()

class StreamLambdaHandler:
    def __init__(self):
        enable_timer()

    def handle_request(self, inputStream, outputStream, context) -> None:
        handler.proxy_stream(inputStream, outputStream, context)

# Usage
stream_lambda_handler = StreamLambdaHandler()
```

Please note that Python does not have direct equivalent of Java's package declaration. Also, Spring and Lambda are AWS services which do not directly translate to Python. This code is a translation of the provided Java code into equivalent Python syntax but it may not be exactly what you would use in a real-world scenario with these technologies.