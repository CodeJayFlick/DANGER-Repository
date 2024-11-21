Here is the translation of the Java code to Python:
```
class FunctionRowObject:
    def __init__(self, function):
        self.function = function

    @property
    def function(self):
        return self.function

    def hash(self):
        return int(self.function.get_id())

    def equals(self, obj):
        if self is obj:
            return True
        if obj is None:
            return False
        if not isinstance(obj, FunctionRowObject):
            return False

        key = self.function.get_id()
        other = obj
        if key != other.function.get_id():
            return False
        return True

    @property
    def key(self):
        return self.function.get_id()

    def __lt__(self, o):
        return (int(self.function.get_id()) < int(o.function.get_id()))
```
Note that I've used Python's built-in `__init__` method to initialize the object, and properties (`@property`) to expose the `function` attribute. The rest of the methods are translated directly from Java.

Also, in Python, we don't need to override the `hashCode()` and `equals()` methods explicitly; instead, we can use the built-in `hash()` function and implement the `<` operator for comparison.

Finally, I've removed the unnecessary imports and licensing information that were present at the top of the original Java code.