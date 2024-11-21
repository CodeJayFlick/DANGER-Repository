Here is a translation of the Java code into equivalent Python:

```Python
class SimpleJavaFunction:
    def __init__(self, signature):
        pass  # No direct equivalent in Python for constructor with parameter

    def __init__(self, name: str, parameters: list, return_type: type, single: bool) -> None:
        self.name = name
        self.parameters = parameters
        self.return_type = return_type
        self.single = single

    @staticmethod
    def execute(e=None, params=None):
        if any(param is None or param == [] for param in params):
            return None  # Return null when empty/null parameter found
        else:
            return SimpleJavaFunction.execute_simple(params)

    @abstractmethod
    def execute_simple(self, params: list) -> object:
        pass

class Signature:
    pass  # No direct equivalent in Python for Java's signature class

class Parameter:
    pass  # No direct equivalent in Python for Java's parameter class

class ClassInfo:
    pass  # No direct equivalent in Python for Java's classinfo class
```

Please note that this is a translation of the code and may not be exact. The `@abstractmethod` decorator does not exist in Python, so I used the built-in abstract method syntax (`pass`) to indicate that these methods should be implemented by subclasses.