Here is the equivalent Python code:

```Python
import logging

logging.basicConfig(level=logging.INFO)

class PriceController:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_price(self):
        self.logger.info("Successfully found price info")
        return "20"

if __name__ == "__main__":
    controller = PriceController()
    print(controller.get_price())
```

Note that Python does not have direct equivalents to Java's annotations or Spring-specific classes. The equivalent functionality is achieved through the use of decorators and logging configuration in Python.

Also, note that this code assumes you are running it as a standalone script (i.e., `if __name__ == "__main__":`). If you're using a web framework like Flask or Django to create an API, your code would be structured differently.