Here is the translation of the given Java code into equivalent Python:

```Python
class LldbRunningEvent:
    def __init__(self, id):
        self.id = id

    def get_thread_id(self):
        return self.id


class AbstractLldbEvent(str):
    pass


# Usage example:
event = LldbRunningEvent("thread-123")
print(event.get_thread_id())  # prints: thread-123
```

Note that Python does not have direct equivalent of Java's abstract classes or interfaces. In this translation, I've used a simple class `AbstractLldbEvent` which inherits from built-in string type in Python to mimic the functionality of an abstract class in Java.

Also note that Python doesn't require explicit constructor declaration like Java. The `__init__` method is automatically called when an object of the class is created.