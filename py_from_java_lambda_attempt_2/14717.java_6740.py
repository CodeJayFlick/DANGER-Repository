Here is the translation of the Java code to Python:
```
class Message:
    def __init__(self, message: str, priority: int):
        self.message = message
        self.priority = priority

    def __lt__(self, other):
        return self.priority < other.priority

    def __str__(self) -> str:
        return f"Message{{'message': '{self.message}', 'priority': {self.priority}}}"
```
Note that I've used Python's built-in `__init__` method to initialize the object, and `__lt__` (less than) special method to implement the comparison logic. The `__str__` method is used to provide a string representation of the object.

Also, in Python, we don't need to explicitly define getters and setters for attributes like Java does with public fields. Instead, you can access the attribute directly using dot notation (e.g., `msg.message`).