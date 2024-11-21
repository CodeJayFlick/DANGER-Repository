Here is the translation of the Java code to Python:
```
import logging

class InitContext:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def lookup(self, service_name: str) -> object:
        if service_name == "jndi/serviceA":
            self.logger.info("Looking up service A and creating new service for A")
            return ServiceImpl("jndi/serviceA")
        elif service_name == "jndi/serviceB":
            self.logger.info("Looking up service B and creating new service for B")
            return ServiceImpl("jndi/serviceB")
        else:
            return None


class ServiceImpl:
    def __init__(self, name: str):
        pass
```
Note that I've used the `logging` module to implement logging in Python. The rest of the code is straightforward translation from Java to Python.

Also, I didn't include any imports for SLF4J or Lombok as they are not necessary in this case and would require additional setup in a Python environment.