Here is the equivalent Python code:

```
class JavaClassConstants:
    MAGIC = 0xcafebabe
    MAGIC_BYTES = bytes([0xca, 0xfe, 0xba, 0xbe])

    T_BOOLEAN = 4
    T_CHAR = 5
    T_FLOAT = 6
    T_DOUBLE = 7
    T_BYTE = 8
    T_SHORT = 9
    T_INT = 10
    T_LONG = 11

    OPERAND_PLACEHOLDER = "&&&"
```

Note that Python does not have a direct equivalent to Java's `public` and `final` keywords, so I omitted them. Also, in Python, we don't need to specify the type of variables (e.g., `int`, `byte[]`) as it is inferred by the interpreter at runtime.