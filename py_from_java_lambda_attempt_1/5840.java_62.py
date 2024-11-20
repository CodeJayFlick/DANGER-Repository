Here is the translation of the Java code to Python:
```
class CharWidth:
    UTF8 = (1,)
    UTF16 = (2,)
    UTF32 = (4,)

    def __init__(self, size):
        self.size = size

    @property
    def size(self):
        return self._size

CharWidth.UTF8 = CharWidth(1)
CharWidth.UTF16 = CharWidth(2)
CharWidth.UTF32 = CharWidth(4)
```
Note that in Python, we don't need to define an `enum` class like Java does. Instead, we can use a simple class with properties and instances.

Also, the `size()` method is replaced by a read-only property (`@property`) called `size`, which returns the value of the `_size` attribute.