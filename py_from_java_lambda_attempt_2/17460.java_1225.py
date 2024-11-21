Here is the translation of the Java code to Python:
```
import io

class IExternalSortFileSerializer:
    def write(self, time_value_pair: 'TimeValuePair') -> None:
        # TO DO: implement writing logic
        pass

    def close(self) -> None:
        # TO DO: implement closing logic
        pass


# Note: TimeValuePair is not a built-in Python type,
# so you would need to define it or use an equivalent data structure.
```
Note that I've kept the `TimeValuePair` as a placeholder, since it's not a native Python type. You'll need to define your own implementation of this class or use an existing one (e.g., from a library) in order to make this code work.

Also, keep in mind that Python doesn't have direct equivalents for Java interfaces and classes with no implementations. Instead, we've defined a Python class `IExternalSortFileSerializer` with two methods: `write` and `close`.