Here is the translation of the Java code into Python:

```Python
class GhidraFileFilter:
    ALL = lambda file_pathname: True  # default implementation that shows all files
    
    def __init__(self):
        pass

    def accept(self, pathname, model):
        return False  # by default, it filters out all files
        
    def get_description(self):
        return "All Files (*)"


# This is the equivalent of Java's interface
class GhidraFileFilterInterface:
    def accept(self, file_pathname, model): pass

    def get_description(self): pass


if __name__ == "__main__":
    ghidra_file_filter = GhidraFileFilter()
```

Please note that Python does not have direct equivalent of Java's interface. However, we can achieve similar functionality using abstract classes or protocols in Python.