Here is the translation of the given Java code into equivalent Python:

```Python
import logging

class ServiceAmbassador:
    def do_remote_function(self, value):
        # implement your remote function here
        pass


class Client:
    def __init__(self):
        self.service_ambassador = ServiceAmbassador()

    def use_service(self, value: int) -> int:
        result = self.service_ambassador.do_remote_function(value)
        logging.info("Service result: %s", str(result))
        return result
```

Please note that the `@Slf4j` annotation in Java is used to automatically inject a logger into your class. In Python, we use the built-in `logging` module for this purpose.

Also, please replace the placeholder code (`pass`) inside the `do_remote_function` method with your actual implementation of remote function call.