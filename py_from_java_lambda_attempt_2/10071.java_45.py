Here is the translation of the Java code to Python:
```
import serializable

class AnonymousCallback(serializable.Serializable):
    serialVersionUID = 1L

    def __init__(self):
        self.anonymous_access_requested = False

    def set_anonymous_access_requested(self, state: bool) -> None:
        self.anonymous_access_requested = state

    def anonymous_access_requested(self) -> bool:
        return self.anonymous_access_requested
```
Note that I used the `serializable` module from Python's standard library to implement serialization. In Java, you would use a similar mechanism like `java.io.Serializable`, but in Python, we don't need an explicit interface or class for serialization; instead, we can simply inherit from the `Serializable` base class.

Also, note that I used type hints (`: bool`) and return types (`-> None`) to indicate the expected behavior of each method. This is not strictly necessary in Python, but it helps with code readability and maintainability.