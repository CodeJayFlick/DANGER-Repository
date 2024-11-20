Here is the equivalent Python code:

```
class MessageData:
    def __init__(self):
        pass

    def __init__(self, m):
        self.set_message(m)

    @property
    def message(self):
        return self._message

    @message.setter
    def set_message(self, message):
        self._message = message
```

Note that Python does not have a direct equivalent to Java's `private` access modifier. In Python, variables are private by convention (i.e., they start with an underscore), but can still be accessed directly from outside the class if desired.