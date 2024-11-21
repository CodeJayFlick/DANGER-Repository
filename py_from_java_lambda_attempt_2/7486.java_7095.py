Here's the equivalent Python code:

```
class FGVertexType:
    BODY = 'BODY'
    ENTRY = 'ENTRY'
    EXIT = 'EXIT'
    GROUP = 'GROUP'
    SINGLETON = 'SINGLETON'

    def is_entry(self):
        return self == FGVertexType.ENTRY or self == FGVertexType.SINGLETON

    def is_exit(self):
        return self == FGVertexType.EXIT or self == FGVertexType.SINGLETON
```

Note that Python does not have an equivalent to Java's `enum` type, so we use a class with constant values instead.