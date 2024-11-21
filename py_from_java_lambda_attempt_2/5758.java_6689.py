Here is the translation of the Java code to Python:

```Python
class BatchGroupLoadSpec:
    def __init__(self, load_spec):
        self.lcs_pair = load_spec.get_language_compiler_spec()
        self.preferred = load_spec.is_preferred()

    def __str__(self):
        if self.lcs_pair is not None:
            return f"{self.lcs_pair}{'*' if self.preferred else ''}"
        else:
            return "none"

    def matches(self, load_spec):
        return (load_spec.get_language_compiler_spec() == self.lcs_pair) or \
               ((load_spec.get_language_compiler_spec() is not None) and
                load_spec.get_language_compiler_spec().equals(self.lcs_pair))

    def __hash__(self):
        prime = 31
        result = 1
        if self.lcs_pair is not None:
            result *= prime + hash(self.lcs_pair)
        else:
            result *= prime
        return result * (1237 if self.preferred else 1231)

    def __eq__(self, other):
        if self == other: 
            return True
        elif other is None: 
            return False
        elif not isinstance(other, BatchGroupLoadSpec): 
            return False
        other = BatchGroupLoadSpec(other)
        if self.lcs_pair is None:
            if other.lcs_pair is not None:
                return False
        else:
            if not self.lcs_pair == other.lcs_pair: 
                return False
        if self.preferred != other.preferred: 
            return False
        return True

    def __lt__(self, other):
        s1 = str(self)
        s2 = str(other)
        return s1 < s2
```

Note that Python does not have a direct equivalent to Java's `Comparable` interface. Instead, you can use the built-in comparison operators (`<`, `>`, etc.) or implement your own custom comparison logic in the `__lt__` method (and similar methods for other comparison operations).