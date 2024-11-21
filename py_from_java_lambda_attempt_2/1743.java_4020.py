Here is the equivalent Python code:

```Python
class ByteOrder:
    eByteOrderInvalid = None
    eByteOrderBig = None
    eByteOrderPDP = None
    eByteOrderLittle = None

    def __init__(self, name):
        self.name = name
        global next_value
        self.value = next_value
        next_value += 1

    @classmethod
    def swig_to_enum(cls, value):
        if isinstance(value, int) and 0 <= value < len(ByteOrder.__dict__):
            return cls.__dict__[list(cls.__dict__.keys())[value]]
        for key in cls.__dict__:
            if getattr(cls, key).value == value:
                return getattr(cls, key)
        raise ValueError(f"No enum {cls.__name__} with value {value}")

    def __str__(self):
        return self.name

    @property
    def swig_value(self):
        return self.value


next_value = 0

ByteOrder.eByteOrderInvalid = ByteOrder("eByteOrderInvalid")
ByteOrder.eByteOrderBig = ByteOrder("eByteOrderBig")
ByteOrder.eByteOrderPDP = ByteOrder("eByteOrderPDP")
ByteOrder.eByteOrderLittle = ByteOrder("eByteOrderLittle")

print(ByteOrder.eByteOrderInvalid.value)  # prints the value of eByteOrderInvalid
```

Note that Python does not have a direct equivalent to Java's `enum` type. The above code uses classes with unique instances as an approximation, but it is not exactly the same thing.