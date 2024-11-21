Here is the translation of the given Java code into equivalent Python:

```Python
class LldbProcessExitedEvent:
    def __init__(self, exit_code):
        self.exit_code = exit_code

    @property
    def state(self):
        return "exited"

# This part doesn't have a direct equivalent in Python. It seems to be related to SWIG (a software wrapper generator) and its StateType enum.
```

Please note that the given Java code is using some concepts like classes, inheritance, methods, properties which are not directly available in Python. Also, it's hard to replicate exactly same functionality without knowing more about what these parts of the original code do.

In this translation:

- The `LldbProcessExitedEvent` class has been defined with an initializer method (`__init__`) that takes one argument (exit_code).
- This class does not have any inheritance or abstract methods.
- A property named "state" is added to represent the state of the event.