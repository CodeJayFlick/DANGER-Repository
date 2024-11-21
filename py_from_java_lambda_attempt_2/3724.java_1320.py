Here is the translation of the Java interface into a Python class:

```Python
class DataTypeSyncListener:
    def __init__(self):
        pass

    def data_type_selected(self, sync_info: dict) -> None:
        """Notification that the given data type was selected."""
        # Your code here to handle the event
```

Note that in Java, interfaces are used to define a contract or blueprint for classes. In Python, we use abstract base classes (ABCs) and protocols from third-party libraries like `typing` to achieve similar functionality. However, since you didn't ask me to create an ABC or protocol, I simply translated the interface into a regular class in Python.

Also note that there is no direct equivalent of Java's interfaces in Python. The closest thing would be abstract base classes (ABCs) and protocols from third-party libraries like `typing`.