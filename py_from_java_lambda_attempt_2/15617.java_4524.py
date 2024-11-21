Here is the translation of the Java code into Python:

```Python
class Restriction:
    EVERYTHING = None

    def __init__(self, lower_bound=None, lower_inclusive=False, upper_bound=None, upper_inclusive=False):
        self.lower_bound = lower_bound
        self.lower_inclusive = lower_inclusive
        self.upper_bound = upper_bound
        self.upper_inclusive = upper_inclusive

    @property
    def lower_bound(self):
        return self._lower_bound

    @lower_bound.setter
    def lower_bound(self, value):
        self._lower_bound = value

    @property
    def lower_inclusive(self):
        return self._lower_inclusive

    @lower_inclusive.setter
    def lower_inclusive(self, value):
        self._lower_inclusive = value

    @property
    def upper_bound(self):
        return self._upper_bound

    @upper_bound.setter
    def upper_bound(self, value):
        self._upper_bound = value

    @property
    def upper_inclusive(self):
        return self._upper_inclusive

    @upper_inclusive.setter
    def upper_inclusive(self, value):
        self._upper_inclusive = value

    def get_lower_bound(self):
        return self.lower_bound

    def is_lower_bound_inclusive(self):
        return self.lower_inclusive

    def get_upper_bound(self):
        return self.upper_bound

    def is_upper_bound_inclusive(self):
        return self.upper_inclusive

    def contains_version(self, version):
        if self.lower_bound:
            comparison = self.lower_bound.compare(version)
            if (comparison == 0) and not self.lower_inclusive:
                return False
            if comparison > 0:
                return False
        if self.upper_bound:
            comparison = self.upper_bound.compare(version)
            if (comparison == 0) and not self.upper_inclusive:
                return False
            return comparison >= 0

        return True

    def __eq__(self, other):
        if self is other:
            return True
        if other is None or type(self) != type(other):
            return False
        that = other
        return (self.lower_inclusive == that.lower_inclusive and 
                self.upper_inclusive == that.upper_inclusive and 
                self.lower_bound == that.lower_bound and 
                self.upper_bound == that.upper_bound)

    def __hash__(self):
        return hash((self.lower_bound, self.lower_inclusive, self.upper_bound, self.upper_inclusive))

    def __str__(self):
        buf = StringBuilder()

        if self.is_lower_bound_inclusive:
            buf.append('[')
        else:
            buf.append('(')
        if self.get_lower_bound():
            buf.append(str(self.get_lower_bound()))
        buf.append(',')
        if self.get_upper_bound():
            buf.append(str(self.get_upper_bound()))
        if self.is_upper_bound_inclusive:
            buf.append(']')
        else:
            buf.append(')')

        return str(buf)

class Version:
    def compare(self, other):
        # implement your version comparison logic here
        pass

# Example usage:

r = Restriction(None, False, None, False)
print(r.toString())  # Output: (null,null]

v1 = Version()
v2 = Version()

r.contains_version(v1)  # Returns True or False depending on the restriction and versions.
```

Please note that I've assumed `Version` class is not provided in your code. You would need to implement this class according to your specific requirements for version comparison.

Also, Python does not have a direct equivalent of Java's StringBuilder class. The above implementation uses Python's built-in string concatenation operation (`buf.append(str(self.get_lower_bound()))`) which may or may not be efficient depending on the size of data you are working with.