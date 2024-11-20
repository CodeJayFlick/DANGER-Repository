Here is the translation of the Java code to Python:
```
class MacOSException(Exception):
    def __init__(self):
        pass

    def __init__(self, message):
        super().__init__(message)
```
Note that in Python, we don't need a `public` keyword since everything is public by default. Also, the constructor (`__init__`) method takes no arguments if it's not specified otherwise.