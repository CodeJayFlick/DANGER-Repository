Here is the translation of the Java code into Python:

```Python
class Version:
    def __init__(self, version):
        self.version = version
        self.snapshot = False if not version.endswith("-SNAPSHOT") else True
        parts = version.split(".", 5)
        comparable = []
        for part in parts[:-1]:
            try:
                comparable.append(int(part))
            except ValueError:
                comparable.append(part)
        comparable.append(parts[-1].replace("-SNAPSHOT", ""))

    def __eq__(self, other):
        if isinstance(other, Version):
            return self.compareTo(other) == 0
        else:
            return False

    def __lt__(self, other):
        if isinstance(other, Version):
            return self.compareTo(other) < 0
        else:
            raise TypeError("Can't compare with this type")

    def compareTo(self, other):
        comparable = [int(x) for x in self.version.split(".")]
        other_comparable = [int(x) for x in other.version.split(".")]

        size = min(len(comparable), len(other_comparable))
        for i in range(size):
            if comparable[i] < other_comparable[i]:
                return -1
            elif comparable[i] > other_comparable[i]:
                return 1

        if len(comparable) < len(other_comparable):
            return -1
        elif len(comparable) > len(other_comparable):
            return 1
        else:
            return 0

    def getMajorVersion(self):
        try:
            return int(self.version.split(".")[0])
        except (IndexError, ValueError):
            return None

    def getMinorVersion(self):
        try:
            return int(self.version.split(".")[1])
        except (IndexError, ValueError):
            return None

    def getIncrementalVersion(self):
        try:
            return int(self.version.split(".")[2])
        except (IndexError, ValueError):
            return None

    def isSnapshot(self):
        return self.snapshot

    def __str__(self):
        return self.version
```

This Python code defines a `Version` class that represents a version string. It has methods to compare two versions (`compareTo`), get the major, minor and incremental versions of a given version (`getMajorVersion`, `getMinorVersion`, `getIncrementalVersion`) and check if it's a snapshot or not (`isSnapshot`). The comparison method is based on the parts of the version string.