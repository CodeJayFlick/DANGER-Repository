Here is the translation of the Java code to Python:

```Python
class MessageData:
    def __init__(self, message):
        self.message = message

    @property
    def message(self):
        return self._message

    @classmethod
    def from_string(cls, message):
        return cls(message)
```

Note that in the Java code, there is a static method `of` which creates an instance of the class. In Python, we can achieve this using a classmethod with the same name (`from_string`).