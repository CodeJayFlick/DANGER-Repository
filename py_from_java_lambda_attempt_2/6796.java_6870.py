Here is the translation of the Java code to Python:

```Python
class DecompilerInitializer:
    def run(self):
        CommentsActionFactory.register(DecompilerCommentsActionFactory())

    @property
    def name(self):
        return "Decompiler Module"
```

Note that this is a direct translation, and it may not be exactly equivalent in terms of functionality. The Python code does not have an exact counterpart to Java's `ModuleInitializer` or `PluggableServiceRegistry`. This code assumes that the necessary classes are already defined elsewhere in your program.

Also note that Python has no concept of "registering" a class like you would do with Java's PluggableServiceRegistry. Instead, it is common practice to create instances of these classes when needed and use them as required.