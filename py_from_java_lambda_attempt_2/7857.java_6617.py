Here is the translation of the given Java code into equivalent Python:

```Python
class MDPinPointerProperty:
    def __init__(self, dmang):
        super().__init__(dmang)

    #def __init__(self, modifierTypeName, dmang) -> None:
    #    super().__init__(modifierTypeName, dmang)
    #
    #def parseCVMod(self, dmang: MDMang) -> None:
    #    pass
    #
    #def emitCVMod(self, builder: StringBuilder) -> None:
    #    pass

    def emit(self, builder):
        if not self.modifierTypeName == "":
            builder.insert(0, "cli::pin_ptr<")
            builder.append(">")
        super().emit(builder)
        return builder.toString()
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or annotations. Also, the equivalent of Java's `@Override` is to simply use the method name with double underscores before and after it (like `__init__`).