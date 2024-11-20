Here is the translation of the Java code to Python:
```python
class PersonSpecifications:
    class AgeBetweenSpec:
        def __init__(self, from_, to):
            self.from_ = from_
            self.to = to

        def to_predicate(self, root, query, cb):
            return cb.between(root.get("age"), self.from_, self.to)

    class NameEqualSpec:
        def __init__(self, name):
            self.name = name

        def to_predicate(self, root, query, cb):
            return cb.equal(root.get("name"), self.name)
```
Note that I've used Python's `class` keyword to define classes, and the `__init__` method is equivalent to Java's constructor. The `to_predicate` methods are similar to Java's `toPredicate` method.

Also, in Python, we don't need to specify types for variables or function parameters like we do in Java.