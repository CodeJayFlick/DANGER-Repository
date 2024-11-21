Here is the equivalent Python code:

```Python
class PdbErrorHandler:
    def __init__(self):
        self.log = None

    def set_log(self, log):
        self.log = log

    def error(self, exception):
        if self.log:
            print(f"PDB XML Error: {exception}")

    def fatalError(self, exception):
        if self.log:
            print(f"PDB XML FatalError: {exception}")

    def warning(self, exception):
        if self.log:
            print(f"PDB XML Warning: {exception}")
```

Note that Python does not have direct equivalents to Java's `package`, `import` statements or the concept of interfaces. The above code is a simple translation of your provided Java class into equivalent Python syntax and functionality.