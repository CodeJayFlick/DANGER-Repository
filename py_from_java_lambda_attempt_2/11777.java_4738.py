Here is the translation of the Java code to Python:
```
class SectionVector:
    def __init__(self, rtl, scope):
        self.next_index = -1
        self.main_pair = {"section": rtl, "scope": scope}
        self.named_pairs = []

    @property
    def main_section(self):
        return self.main_pair["section"]

    def get_named_section(self, index):
        return self.named_pairs[index]["section"]

    @property
    def main_pair(self):
        return self.main_pair

    def get_named_pair(self, i):
        return self.named_pairs[i]

    def set_next_index(self, i):
        self.next_index = i

    @property
    def max_id(self):
        return len(self.named_pairs)

    def append(self, rtl, scope):
        while len(self.named_pairs) <= self.next_index:
            self.named_pairs.append({"section": None, "scope": None})
        self.named_pairs[self.next_index] = {"section": rtl, "scope": scope}
```
Note that I've used Python's built-in `list` type to represent the `VectorSTL<rtlPair>` in Java. In Python, we don't need explicit bounds checking like in Java, so I removed those checks.

Also, I replaced the `RtlPair` class with a simple dictionary (`{"section": rtl, "scope": scope}`) since it seems that `RtlPair` is just a container for two values (section and scope). If you want to keep the `RtlPair` class, please let me know!