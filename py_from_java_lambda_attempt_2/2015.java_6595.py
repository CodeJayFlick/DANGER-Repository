Here is the translation of the given Java code into equivalent Python:

```Python
class JdiStateListener:
    def __init__(self):
        pass

    def state_changed(self, new_state: int, cause) -> None:
        """The state has changed because of the given cause"""
        # Your implementation here
        print(f"New State: {new_state}, Cause: {cause}")

# Note that Python does not have a direct equivalent to Java's TriConsumer.
# However, you can use a custom class or function with three parameters:
class JdiCause:
    pass

def state_changed(old_state: int, new_state: int, cause: JdiCause) -> None:
    """The state has changed because of the given cause"""
    # Your implementation here
    print(f"Old State: {old_state}, New State: {new_state}, Cause: {cause}")

# Example usage:
jdi_listener = JdiStateListener()
state_changed(1, 2, JdiCause())
```

This Python code defines a class `JdiStateListener` with a method `state_changed`, which is equivalent to the Java interface. The Python version does not have direct support for triple consumers like in Java's TriConsumer; instead, you can use custom classes or functions as shown above.