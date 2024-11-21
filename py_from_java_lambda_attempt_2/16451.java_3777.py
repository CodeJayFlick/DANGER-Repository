Here is the translation of the Java code to Python:
```
class TruncateCommittedEntryException(Exception):
    def __init__(self, index: int, committed: int) -> None:
        super().__init__(
            f"The committed entries cannot be truncated: parameter: {index}, commitIndex : {committed}"
        )
```
Note that I used the `f` string notation to create a formatted string, which is similar to Java's `String.format()` method.