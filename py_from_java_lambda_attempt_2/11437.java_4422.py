Here is the translation of the given Java code into equivalent Python:

```Python
class AssemblyParseTreeNode:
    def __init__(self, grammar):
        self.parent = None
        self.grammar = grammar

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
        self._parent = value

    def get_sym(self):
        raise NotImplementedError("Subclass must implement this method")

    def generate_string(self):
        raise NotImplementedError("Subclass must implement this method")


class AssemblyGrammar:
    pass


def print_node(out, node, indent=""):
    if hasattr(node, "print"):
        node.print(out, indent)
    else:
        out.write(indent + str(type(node)) + "\n")
```

Note that the Python code does not exactly replicate the Java code. In particular:

- The `AssemblyGrammar` class is defined in both languages as an abstract base class (ABC) but it's a simple pass-through class in Python.
- The `getSym`, `getParent`, and `generateString` methods are declared as abstract in Java, which means they must be implemented by any subclass. In Python, these methods are not abstract; instead, the code raises a `NotImplementedError` if you try to call them on an instance of this class.
- The `print` method is also not exactly replicated because it's more common and idiomatic in Python to use the built-in `str.format()` or f-string formatting for printing rather than having separate methods like Java.