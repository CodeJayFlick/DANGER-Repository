Here is the translation of the Java code to Python:
```
class Decision:
    def __init__(self, value: str, decision_path: list[str], source: str):
        self.value = value
        self.decision_path = decision_path
        self.source = source

    @property
    def value(self) -> str:
        return self.value

    @property
    def source(self) -> str:
        return self.source

    @property
    def decision_path(self) -> list[str]:
        return self.decision_path

    def get_decision_path_string(self) -> str:
        return "\n".join(self.decision_path)
```
Note that I used the `@property` decorator to create read-only properties for the `value`, `source`, and `decision_path` attributes. This is equivalent to the getter methods in Java.

I also replaced the `StringBuilder` class with a simple string concatenation using the `\n`.join() method, which creates a new string by joining all elements of the list with newline characters (`\n`).