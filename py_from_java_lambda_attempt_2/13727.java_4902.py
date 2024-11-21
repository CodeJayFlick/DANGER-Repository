Here is the translation of the Java code to Python:

```Python
class Captain:
    def __init__(self):
        self.rowing_boat = None

    @property
    def rowing_boat(self):
        return self._rowing_boat

    @rowing_boat.setter
    def rowing_boat(self, value):
        self._rowing_boat = value

    def row(self):
        if self.rowing_boat is not None:
            self.rowing_boat.row()
```

Note that Python does not have a direct equivalent to Java's `@Setter`, `@NoArgsConstructor` and `@AllArgsConstructor`. These annotations are used by Lombok, a third-party library in Java. In the above code, I've implemented these features manually using Python's property decorator.

Also note that there is no concept of "final" class or method in Python.