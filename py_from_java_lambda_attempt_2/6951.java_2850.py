Here is the translation of the Java code to Python:
```
class PrimaryDecompilerProvider:
    def __init__(self, plugin):
        super().__init__(plugin, True)

    def is_connected(self) -> bool:
        return True
```
Note that I've used the `super()` function to call the parent class's constructor (`__init__` method), and also defined a simple `is_connected` method with a boolean return value.