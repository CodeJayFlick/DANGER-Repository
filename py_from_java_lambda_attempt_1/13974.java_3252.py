Here is the translation of the Java code to Python:

```Python
from datetime import datetime

class StartingData:
    def __init__(self, when):
        self.when = when

    @property
    def when(self):
        return self._when

    @classmethod
    def of(cls, when):
        return cls(when)
```

Note that Python does not have a direct equivalent to Java's `@RequiredArgsConstructor` or `@Getter`. In the above code, I used Python's property decorator (`@property`) to achieve similar functionality.