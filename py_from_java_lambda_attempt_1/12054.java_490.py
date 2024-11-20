Here's a translation of the Java code into equivalent Python:

```Python
class StackReferenceDB:
    def __init__(self, program, from_addr, to_addr, ref_type, op_index, source_type, is_primary, symbol_id):
        pass  # Note: In Python, we don't need explicit constructors like in Java.

    def get_stack_offset(self):
        return int(to_addr.get_offset())

    def is_stack_reference(self):
        return True
```

Note that I've omitted the `super` call and constructor parameters as they are not necessary in Python. Also, there's no direct equivalent of Java's `@Override` annotation in Python; it's just a convention to use this syntax when overriding methods from parent classes.

The rest of the code is straightforward translation: class definition, method definitions with their corresponding bodies.