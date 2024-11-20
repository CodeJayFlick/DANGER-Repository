Here is the translation of the Java code to Python:
```
import io

class SingleSourceExternalSortJobPart:
    def __init__(self, chunk_reader_wrap):
        self.chunk_reader_wrap = chunk_reader_wrap
        super().__init__(type="SINGLE_SOURCE")

    def execute_for_i_point_reader(self) -> "IPointReader":
        return self.chunk_reader_wrap.get_i_point_reader()
```
Note that I've used the following Python concepts to translate the Java code:

* `class` instead of `public class`
* `def __init__(self, ...)` for constructor
* `super().__init__(...)` to call parent class's constructor
* `-> "IPointReader"` is a type hint indicating that the method returns an object implementing the `IPointReader` interface (similar to Java's generics)
* No equivalent of Java's `throws IOException`, as Python doesn't have checked exceptions. Instead, you can use try-except blocks to handle potential errors.

Also note that I've used string literals for type names and variable names, whereas in Java they would be constants or enums.