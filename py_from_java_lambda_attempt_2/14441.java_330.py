Here is the translation of the Java code to Python:
```
import logging

class HolderNaive:
    def __init__(self):
        self.heavy = None
        logging.info("HolderNaive created")

    @property
    def heavy(self):
        if self.heavy is None:
            self.heavy = Heavy()
        return self.heavy


class Heavy:
    pass  # No implementation needed for this example, just a placeholder class
```
Note that I did not include any logging configuration or setup in the Python code. In Java, you would typically use a logging framework like Log4j to configure and use loggers. In Python, you can simply import the `logging` module and use its functions (like `info`) without additional setup.

Also, I used the `@property` decorator to create a getter for the `heavy` attribute in the `HolderNaive` class. This is equivalent to Java's public method with the same name as the field (`getHeavy()`).