Here is the translation of the Java code to Python:
```
class ShowTTLPlan:
    def __init__(self, storage_groups):
        self.storage_groups = storage_groups
        super().__init__("TTL")

    @property
    def paths(self):
        return None  # equivalent to getPaths() returning null

    @property
    def storage_groups(self):
        return self._storage_groups
```
Note that I've used Python's `@property` decorator to create read-only properties for the `paths` and `storage_groups` attributes. This is similar to Java's getter methods, but with a more concise syntax.

Also, in Python, we don't need to explicitly define constructors or destructors like we do in Java. The `__init__` method serves as both constructor and initializer.

Finally, I've used the `super()` function to call the parent class's constructor (in this case, `ShowPlan`) with a string argument `"TTL"`.