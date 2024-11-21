Here is the translation of the given Java code into Python:

```Python
class Message:
    def __init__(self, msg):
        self.msg = msg

    @property
    def message(self):
        return self.msg

    def __str__(self):
        return str(self.msg)
```

Note that in this translation, I have used the `@property` decorator to create a getter for the `msg` attribute. This is equivalent to Java's `@Getter` annotation. The `__init__` method initializes an instance of the class with a given message string.