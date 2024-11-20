Here is the translation of the given Java code into equivalent Python:

```Python
class MDThrowAttribute:
    def __init__(self):
        self.args_list = None
        self.has_throw = True

    def parse(self, dmang):
        if dmang.peek() == 'Z':
            dmang.increment()
            self.has_throw = False
        else:
            self.args_list.parse(dmang)

    def insert(self, builder):
        if self.has_throw:
            builder.append("throw (")
            self.args_list.insert(builder)
            builder.append(")")
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. Also, Python classes do not require explicit constructors (`__init__`) to be defined. The equivalent of a constructor in Python is simply defining an instance variable with the same name as the class.

The `MDMang` and `MDArgumentsList` are replaced by simple variables since their exact functionality was not provided in the given Java code.