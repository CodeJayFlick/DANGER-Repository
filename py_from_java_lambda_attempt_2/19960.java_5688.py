Here is the translation of the given Java code into Python:

```Python
import re

class Version:
    def __init__(self, *version):
        if len(version) < 1 or len(version) > 3:
            raise ValueError("Versions must have a minimum of 2 and a maximum of 3 numbers")
        self.version = [int(x) for x in version]
        self.postfix = None

    def __init__(self, major, minor, postfix=None):
        self.version = [major, minor]
        if postfix is not None:
            self.postfix = str(postfix)

    @classmethod
    def from_string(cls, s):
        pattern = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))? ?(.*)")
        match = pattern.match(s.strip())
        if not match:
            raise ValueError(f"'{s}' is not a valid version string")

        self = cls(int(match.group(1)), int(match.group(2)))
        if match.group(3):
            self.version.append(int(match.group(3)))
        self.postfix = match.group(4) or None

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, Version):
            return False
        return self.compareTo(other) == 0

    def __hash__(self):
        pf_hash = hash(self.postfix) if self.postfix else 0
        return sum(x * 31 for x in self.version) + pf_hash

    def compareTo(self, other):
        if other is None:
            return 1
        for i in range(len(self.version)):
            if self.version[i] > other.version[i]:
                return 1
            elif self.version[i] < other.version[i]:
                return -1
        if not self.postfix and not other.postfix:
            return 0
        if self.postfix is None:
            return -1
        if other.postfix is None:
            return 1
        return self.postfix.casefold().compare(other.postfix.casefold())

    def compareTo(self, *other):
        for i in range(len(self.version)):
            if self.version[i] > (i >= len(other) and 0 or other[i]):
                return 1
            elif self.version[i] < (i >= len(other) and 0 or other[i]):
                return -1
        return 0

    def isSmallerThan(self, other):
        return self.compareTo(other) < 0

    def isLargerThan(self, other):
        return self.compareTo(other) > 0

    @property
    def isStable(self):
        return not self.postfix or self.postfix.startswith("-")

    @property
    def major(self):
        return self.version[0]

    @property
    def minor(self):
        return self.version[1]

    @property
    def revision(self):
        if len(self.version) == 2:
            return 0
        else:
            return self.version[2]

    def __str__(self):
        pf = self.postfix or ""
        return f"{self.version[0]}.{self.version[1]}{'' if len(self.version) < 3 else '.' + str(self.version[2])}{pf.startswith('-') and pf or ' ' + pf}"

    @classmethod
    def compare(cls, v1, v2):
        return Version(v1).compareTo(Version(v2))
```

Please note that Python does not have a direct equivalent to Java's `@Override` annotation. The method overriding is done by naming the new method exactly like the one in the parent class (in this case, `__eq__`, `__hash__`, etc.).