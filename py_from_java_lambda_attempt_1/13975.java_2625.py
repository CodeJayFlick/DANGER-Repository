Here is the translation of the Java code to Python:
```
import datetime

class StoppingData:
    def __init__(self, when: datetime.datetime):
        self.when = when

    @property
    def when(self) -> datetime.datetime:
        return self._when

    @classmethod
    def of(cls, when: datetime.datetime) -> 'StoppingData':
        return cls(when)
```
Note that I used the `datetime` module from Python's standard library to represent dates and times. The rest of the code is straightforward translation:

* The Java class becomes a Python class with an initializer (`__init__`) method.
* The Java fields become instance variables in Python, accessed using dot notation (e.g., `self.when`).
* The Java getter methods are replaced by Python's built-in property decorator (`@property`). This allows you to access the underlying attribute as if it were a separate method.
* The Java static factory method becomes a classmethod in Python, with the same signature and behavior.