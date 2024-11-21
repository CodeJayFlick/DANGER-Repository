Here is the translation of the given Java code into equivalent Python:

```Python
class OtherSpace:
    def __init__(self, t, nm=None, ind=0):
        super().__init__(t, 'IPTR_PROCESSOR', nm, 8, 1, ind, 0, 0)
        self.clear_flags('heritaged')
        self.set_flags('is_otherspace')

    @classmethod
    def from_translate(cls, t):
        return cls(t)

    def print_raw(self, s, offset):
        s.write("0x")
        s.write(hex(offset))
        return self.get_trans().get_default_size()

    def save_xml(self, s):
        s.write("<space_other")
        self.save_basic_attributes(s)
        s.write("/>")
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of a class extending another. Also, Python uses indentation to denote block-level structure instead of curly braces.

The equivalent Python code is written in classes and methods (similarly as in Java), but with some differences:

- The constructor (`__init__`) method has been added.
- There are no direct equivalents for `super`, so the superclass's constructor must be called using the `super()` function.
- Methods like `clearFlags` and `setFlags` have been replaced by equivalent Python code, which sets or clears flags as needed.