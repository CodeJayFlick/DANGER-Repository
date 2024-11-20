Here is the equivalent Python code:

```
class OptimizeRecord:
    def __init__(self):
        self.writeop = -1
        self.readop = -1
        self.inslot = -1
        self.writecount = 0
        self.readcount = 0
        self.writesection = -2
        self.readsection = -2
        self.opttype = -1

    def __str__(self):
        return f"{{writeop={self.writeop}, readop={self.readop}, inslot={self.inslot}, writecount={self.writecount}, readcount={self.readcount}, opttype={self.opttype}}}"
```

Note that Python does not have a direct equivalent to Java's `@Override` annotation, as it is primarily used for method overriding in statically-typed languages. In Python, you can simply define the method without any special notation.