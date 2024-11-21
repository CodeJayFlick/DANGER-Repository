Here is the translation of the given Java code into equivalent Python:

```Python
class AssemblyParseAcceptResult:
    def __init__(self, tree):
        self.tree = tree

    @property
    def isError(self):
        return False

    @property
    def get_tree(self):
        return self.tree

    def __str__(self):
        baos = io.BytesIO()
        print(tree, file=baos)
        return baos.getvalue().decode('utf-8')
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of classes being part of a package. The equivalent code in Python is simply defining a class and its methods.

Also note that there are some differences between how you would implement certain concepts in Java versus Python:

- In Java, you can use access modifiers like public to control visibility of variables and methods from outside their declaring class. In Python, this concept does not exist; all members of a class (methods and data) are accessible by default.

- In Java, you have the option to override inherited methods using the @Override annotation. This is also true in Python for method overriding: if your subclass provides an implementation for a method that's already defined in its superclass, it will be called when the same method name is invoked on instances of the subclass.