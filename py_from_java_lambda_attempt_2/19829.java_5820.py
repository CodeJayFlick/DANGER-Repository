Here is the translation of the Java code to Python:
```
import logging

class ArgsMessage:
    def __init__(self, key):
        self.key = key

    def __str__(self):
        raise NotImplementedError("Not implemented")

    def __str__(self, *args):
        try:
            value = self.get_value()
            if value is None:
                return str(self.key)
            else:
                return f"{value}".format(*args)
        except Exception as e:
            logging.error(f"The formatted message '{self.key}' uses an illegal format: {e}")
            print("[Skript] " + str(e))
            raise

    def get_value(self):
        # This method is not implemented in the original Java code
        pass
```
Note that I had to make some assumptions about the `get_value()` method, as it was not provided in the original Java code. In Python, we typically use a separate class or function for error handling and logging, rather than catching exceptions at every level of the program.

Also, I used the f-string formatting syntax (`f"{value}".format(*args)`) which is available in Python 3.6+. If you're using an earlier version of Python, you can use the `str.format()` method instead.