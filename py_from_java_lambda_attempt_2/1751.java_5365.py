Here is the equivalent Python code:

```Python
class Encoding:
    e_encoding_invalid = "eEncodingInvalid"
    e_encoding_uint = "eEncodingUint"
    e_encoding_sint = "eEncodingSint"
    e_encoding_ieee754 = "eEncodingIEEE754"
    e_encoding_vector = "eEncodingVector"

    def __init__(self, name):
        self.name = name
        Encoding._next_value += 1

    @classmethod
    def swig_to_enum(cls, value):
        if value < len(Encoding.swig_values) and value >= 0:
            return Encoding.swig_values[value]
        for i in range(len(Encoding.swig_values)):
            if Encoding.swig_values[i].value == value:
                return Encoding.swig_values[i]
        raise ValueError(f"No enum {cls.__name__} with value {value}")

    def __str__(self):
        return self.name

    @property
    def value(self):
        return self._value

    swig_values = [
        e_encoding_invalid,
        e_encoding_uint,
        e_encoding_sint,
        e_encoding_ieee754,
        e_encoding_vector,
    ]
    _next_value = 0


# usage:
e1 = Encoding(e_encoding_invalid)
print(f"{e1.name} has value {e1.value}")
```

Note that Python does not have a direct equivalent to Java's `final` keyword, so I did not include it in the code. Also, Python does not support static variables at the class level like Java does with `private static`. Instead, we use a list comprehension and instance methods to achieve similar functionality.