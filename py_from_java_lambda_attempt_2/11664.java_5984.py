Here is the translation of the Java code to Python:
```
class SleighError(Exception):
    def __init__(self, message: str, location: 'Location') -> None:
        super().__init__(message)
        self.location = location
```
Note that I used a custom `Exception` class named `SleighError`, and the constructor takes two arguments: `message` (a string) and `location` (an instance of some other Python object, which we'll assume is defined elsewhere in your code). The rest of the translation was straightforward.