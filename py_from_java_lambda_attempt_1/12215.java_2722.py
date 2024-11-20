Here is the translation of the Java code into Python:

```Python
class InstructHash:
    def __init__(self, inst, bl, ind):
        self.is_matched = False
        self.index = ind
        self.block = bl
        self.instruction = inst
        self.n_grams = None
        self.hash_entries = {}

    @property
    def block(self):
        return self._block

    @block.setter
    def block(self, value):
        self._block = value

    def all_unknown(self, length):
        return self.block.all_unknown(self.index, length)

    def clear_sort(self):
        self.hash_entries = {}

    def clear_ngrams(self, sz):
        self.n_grams = [None] * sz
```

Note that Python does not have a direct equivalent to Java's `protected` access modifier. In this translation, I've used the convention of prefixing protected attributes and methods with an underscore (`self._block`, for example). This is a common pattern in Python programming.

Also note that Python does not require explicit type declarations like Java does. The types are inferred by the interpreter at runtime.