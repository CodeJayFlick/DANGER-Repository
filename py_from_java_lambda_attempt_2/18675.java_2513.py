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

Note that Python does not have a direct equivalent to Java's `private` access modifier. In this code, I've used the convention of prefixing instance variables with an underscore (`_`) to indicate they are intended to be private.