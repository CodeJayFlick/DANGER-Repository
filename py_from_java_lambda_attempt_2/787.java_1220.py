Here's a translation of the Java interface into equivalent Python code:

```Python
class DbgModelTargetSymbol:
    def is_constant(self):
        pass  # To be implemented by subclasses

    def get_value(self) -> 'Address':
        raise NotImplementedError("Method not yet implemented")

    def get_size(self) -> int:
        raise NotImplementedError("Method not yet implemented")
```

Note that Python does not have a direct equivalent to Java's interface concept. Instead, we define an abstract base class (`DbgModelTargetSymbol`) with methods declared as `pass` or raising `NotImplementedError`. This is similar in spirit to the original Java code, but it's more flexible and open-ended.

In this translation:

- The `@Override` annotations are not needed because Python does not have a concept of method overriding.
- We use the `-> 'Address'` syntax for type hinting (Python 3.5+), which is similar to Java's return type declaration, but it's optional and only used by static analysis tools or IDEs.
- The `public` access modifier is not needed in Python because all methods are public unless explicitly marked as private (`__method_name`).