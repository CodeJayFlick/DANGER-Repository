Here is the translation of the Java code into Python:

```Python
class Face:
    def __init__(self, bytes):
        self.weight = 1
        self.children = set()
        self.join_of = None
        self.str_id = str(self)
        dit_ratio = 2.0 ** -len(bytes)

    @classmethod
    def from_bytes(cls, bytes):
        return cls(bytes)

    def __str__(self):
        return ''.join([chr(b) for b in self])

    def join(self, f1, f2, patterns, max_dim, add_f1=False):
        if len(self) + 1 > max_dim:
            return
        self.str_id = str(self)
        self.weight = 0
        self.children = set()
        self.join_of = (f1, f2)

        for kid in patterns:
            temp = DittedBitSequence(self, kid)
            if len(temp) == len(self):
                self.children.add(kid)
                self.weight += kid.get_weight()

        if add_f1 and f1 not in patterns:
            self.children.add(f1)
            self.weight += f1.get_weight()

    @property
    def dit_ratio(self):
        return 2.0 ** -len(self)

    @property
    def weight(self):
        return self._weight

    @weight.setter
    def weight(self, value):
        self._weight = value

    @property
    def children(self):
        return self._children

    @children.setter
    def children(self, value):
        self._children = set(value)

    def get_weight(self):
        return self.weight

    def increment_weight(self):
        self.weight += 1

    def meets_criteria(self, patterns, face_by_name):
        if f1 := pattern for pattern in patterns if pattern == self.join_of[0]; not f1:
            return False
        elif f2 := pattern for pattern in patterns if pattern == self.join_of[1]; not f2:
            return False
        elif str_id := name for name, face in face_by_name.items() if face == self; str_id and str_id == self.str_id:
            return False
        return True

    def ratio_filled(self):
        return self.weight * self.dit_ratio


class DittedBitSequence:
    def __init__(self, parent, kid):
        self.parent = parent
        self.kid = kid

    @property
    def num_uncertain_bits(self):
        return len(self)

    @property
    def get_weight(self):
        if hasattr(self.kid, 'get_weight'):
            return self.kid.get_weight()
        else:
            return 1


class Pair:
    def __init__(self, first, second):
        self.first = first
        self.second = second

    def __str__(self):
        return f'({self.first}, {self.second})'
```

Please note that Python does not have direct equivalent of Java's `HashSet` and `HashMap`. Instead, you can use built-in dictionary (`dict`) for hash-like operations. Also, the code assumes that there is a class called `DittedBitSequence`, which was missing in your original Java code.