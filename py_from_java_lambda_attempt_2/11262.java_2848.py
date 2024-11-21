Here is the translation of the given Java code into equivalent Python:

```Python
class PluginConstructionException(Exception):
    """ Exception thrown when a an error occurs during the construction 
        of a plugin.
    """

    def __init__(self, class_name: str, details: str) -> None:
        super().__init__("Cannot load plugin " + class_name + ": " + details)
```

Note that Python does not have direct equivalent to Java's `package` statement. Also, the concept of a package in Python is different from what it means in Java. In Python, you can use modules and packages as needed.

The rest of the code remains similar with some minor adjustments for Python syntax.