Here is the translation of the given Java code into Python:

```Python
class TestUniversalIdGenerator:
    START_ID = 1000
    _id = START_ID
    _checkpoint = START_ID

    def __init__(self):
        self.install_generator(self)

    def get_next_id(self):
        return UniversalID(_id + 1)

    def restore(self):
        self._id = self._checkpoint

    def checkpoint(self):
        self._checkpoint = self._id


class UniversalID:
    def __init__(self, id_value):
        self.id_value = id_value
```

Please note that Python does not have direct equivalent of Java's `package` statement. Also, the concept of static variables in Java is handled using class-level attributes in Python.