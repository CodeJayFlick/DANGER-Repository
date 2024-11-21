Here is the translation of the Java code into Python:

```Python
class AssemblyExtendedNonTerminal:
    def __init__(self, start, nt, end):
        self.name = f"{start}[{nt.name}]{end}"
        self.nt = nt
        self.end = end

    def get_name(self):
        if self.end == -1:
            return self.nt.get_name()
        else:
            return self.name

    def __str__(self):
        if self.end == -1:
            return str(self.nt)
        else:
            return self.name
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements, or the license information. Also, in Python, we don't need to specify types of variables like we do in Java.