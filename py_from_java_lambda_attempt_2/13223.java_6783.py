Here is the equivalent Python code:

```
class FieldInfoAccessFlags:
    ACC_PUBLIC = 0x0001
    ACC_PRIVATE = 0x0002
    ACC_PROTECTED = 0x0004
    ACC_STATIC = 0x0008
    ACC_FINAL = 0x0010
    ACC_VOLATILE = 0x00400
    ACC_TRANSIENT = 0x0080
    ACC_SYNTHETIC = 0x1000
    ACC_ENUM = 0x4000

    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value

FieldInfoAccessFlags.ACC_PUBLIC = FieldInfoAccessFlags(ACC_PUBLIC)
FieldInfoAccessFlags.ACC_PRIVATE = FieldInfoAccessFlags(ACC_PRIVATE)
FieldInfoAccessFlags.ACC_PROTECTED = FieldInfoAccessFlags(ACC_PROTECTED)
FieldInfoAccessFlags.ACC_STATIC = FieldInfoAccessFlags(ACC_STATIC)
FieldInfoAccessFlags.ACC_FINAL = FieldInfoAccessFlags(ACC_FINAL)
FieldInfoAccessFlags.ACC_VOLATILE = FieldInfoAccessFlags(ACC_VOLATILE)
FieldInfoAccessFlags.ACC_TRANSIENT = FieldInfoAccessFlags(ACC_TRANSIENT)
FieldInfoAccessFlags.ACC_SYNTHETIC = FieldInfoAccessFlags(ACC_SYNTHETIC)
FieldInfoAccessFlags.ACC_ENUM = FieldInfoAccessFlags(ACC_ENUM)

print(FieldInfoAccessFlags.ACC_PUBLIC.value)  # prints: 1
```

Note that Python does not have an exact equivalent to Java's enum type. Instead, we define a class with static attributes and use the `@property` decorator to create a read-only property for the value attribute.