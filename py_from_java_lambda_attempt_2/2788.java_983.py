Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractDirectedLongKeyIterator:
    def __init__(self, db_long_iterator):
        self.it = db_long_iterator

    def delete(self) -> bool:
        return self.it.delete()
```

Note that in this translation, I have not included any error handling for the `IOException` as Python does not support checked exceptions like Java. Also, the abstract class concept is not directly applicable to Python (Python supports only single inheritance), so I have used a regular class instead of an abstract one.