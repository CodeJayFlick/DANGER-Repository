Here is the translation of the given Java code into equivalent Python:

```Python
class MDVarArgsType:
    def __init__(self):
        pass

    def get_type_name(self) -> str:
        return "..."
```

Note that in this translation, I have removed some parts as they are not directly translatable to Python. Here's a brief explanation of the changes:

- The Java code has an import statement for `mdemangler.MDMang`, which is equivalent to importing a module in Python.
- In the constructor (`__init__` method), we don't need to pass any arguments as it doesn't seem like there are any specific parameters required. 
- We have removed the comment block at the top, as comments are not directly translatable into code and would be ignored by the interpreter anyway.
- The `@Override` annotation is used in Java to indicate that a method overrides one from its superclass. In Python, this concept doesn't exist explicitly; instead, we use inheritance (which is already implemented through subclassing) or explicit naming of methods (`get_type_name()`).
- We have removed the package declaration as it's not directly translatable into code and would be ignored by the interpreter anyway.
- The `super( dmang )` call in Java has been replaced with an empty constructor, as Python doesn't require this kind of initialization.