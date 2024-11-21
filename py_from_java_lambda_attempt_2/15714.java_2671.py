Here is the translation of the Java code to Python:

```Python
class FixedTracker:
    def __init__(self, value):
        self.value = value

    @property
    def new_value(self):
        return self.value


def fixed_tracker_builder(value=None):
    tracker = FixedTracker(value)
    return tracker


if __name__ == "__main__":
    builder = fixed_tracker_builder(10.0)  # create a builder with initial value of 10.0
    print(builder.new_value)  # prints: 10.0

```

Note that Python does not have direct equivalent to Java's `package`, `class` and `interface`. In this translation, I've used the conventional naming conventions for classes in Python.

Also note that there is no need for a separate builder class as it was needed in Java due to its lack of constructor overloading.