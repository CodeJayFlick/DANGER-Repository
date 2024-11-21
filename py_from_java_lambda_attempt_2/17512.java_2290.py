Here is the translation of the Java interface `UDTF` into a Python class:

```Python
class UDTF:
    def __init__(self):
        pass

    def before_start(self, parameters: dict, configurations: dict) -> None:
        # Your code here
        pass

    def transform_row(self, row: dict, collector: callable) -> None:
        # Your code here
        pass

    def transform_window(self, window: dict, collector: callable) -> None:
        # Your code here
        pass

    def terminate(self, collector: callable) -> None:
        # Your code here
        pass
```

Note that Python does not have a direct equivalent to Java's interfaces. Instead, we can use abstract base classes (ABCs) or protocols to define the interface for our class.

In this translation, I used `before_start`, `transform_row`, and `transform_window` as method names instead of `beforeStart`, `transform(Row, PointCollector)`, and `transform(RowWindow, PointCollector)` respectively. This is because Python's method naming convention does not use camel case like Java.

Also note that the `@SuppressWarnings("squid: S112")` annotation in the original code has been removed as it is specific to Java and its static analysis tool SonarQube.