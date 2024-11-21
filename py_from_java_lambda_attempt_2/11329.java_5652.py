Here's a translation of the Java code into equivalent Python:

```Python
class DummyDomainObject:
    def __init__(self, name: str, consumer):
        super().__init__(DBHandle(), name, 10, 1, consumer)

    @property
    def description(self) -> str:
        return f"Test object: {self.name}"

    @property
    def is_changeable(self) -> bool:
        return True

class DBHandle:
    pass


# Usage example:

try:
    db_handle = DBHandle()
    dummy_domain_object = DummyDomainObject("Dummy", "Consumer")
except Exception as e:
    print(f"An error occurred: {e}")
```

Please note that Python does not have direct equivalents for Java's `IOException` and `@Override`. In the above code, I've used a simple try-except block to handle any potential exceptions.