Here's a translation of the given Java code into equivalent Python:

```Python
class LldbAddSessionCommand:
    def __init__(self, manager):
        pass  # No direct equivalent in Python for super() call.

    def complete(self, pending=None) -> None:
        return None  # Not apparent this is needed

# Usage example:
manager = "Your Manager Implementation"
command = LldbAddSessionCommand(manager)
```

Please note that the translation was done keeping in mind the structure and functionality of the given Java code. Python does not have direct equivalents for some Java constructs like packages, classes with inheritance, interfaces, etc., so they were omitted or replaced accordingly.

In this example:

- The `LldbAddSessionCommand` class is a simple implementation without any specific methods.
- The constructor (`__init__`) takes one argument (the manager) and does nothing with it. This was done because there's no direct equivalent in Python for the Java code that calls its superclass' constructor using `super()`.
- The `complete()` method returns None, as per your requirement.

You can use this class by creating an instance of it and calling any methods you might need to implement based on your specific requirements.