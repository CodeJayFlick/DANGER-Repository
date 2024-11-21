Here is the translation of the Java code to Python:
```
class ID:
    def __new__(cls, obj):
        return cls(obj)

    def __init__(self, obj):
        self.obj = obj

    @property
    def object(self):
        return self.obj

    def __hash__(self):
        return hash(id(self.obj))

    def __eq__(self, other):
        if not isinstance(other, ID):
            return False
        that = other
        return self.obj == that.obj
```
Note:

* In Python, we don't need a `public` keyword as everything is public by default.
* The `<T>` syntax in Java is equivalent to the type hinting syntax in Python (`T: Type[T]`) but since Python doesn't have generics like Java does, I removed it. If you want to add some static typing using mypy or other tools, that's a different story!
* In `__new__`, we're creating an instance of the class and returning it.
* The `@property` decorator is used to create a read-only property for the `object` attribute.
* Python doesn't have an exact equivalent to Java's `System.identityHashCode()` method, so I used the built-in `hash(id(obj))` function as a workaround. This will return the hash code of the object instance itself (not its contents).
* The `__eq__` method is similar to the one in Java; we check if the other object is an instance of our class and then compare their internal state (`self.obj`) for equality.

This Python code should provide equivalent functionality to the original Java code.