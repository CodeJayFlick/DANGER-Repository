Here is the translation of the given Java code into equivalent Python:

```Python
class MDInt32DataType:
    def __init__(self):
        pass

    @property
    def type_name(self) -> str:
        return "__int32"
```

Note that in this translation, I have removed the `MDMang` and `super()` calls as they are not directly equivalent to Python. The `@Override` annotation is also not necessary in Python because it does not support method overriding like Java does.

Also note that there's no direct equivalent of Java's `extends MDExtendedType` syntax in Python, so I have removed the inheritance part from the class definition.