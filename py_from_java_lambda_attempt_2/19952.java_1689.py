Here is the translation of the Java code to Python:

```Python
class SoundUtils:
    def __init__(self):
        pass  # equivalent to private constructor in Java

    @staticmethod
    def parse(s: str) -> 'Sound':
        return EnumUtils.parse(Sound, s)

    @staticmethod
    def to_string(sound: 'Sound', flags: int) -> str:
        return EnumUtils.to_string(sound, flags)

    @staticmethod
    def get_all_names() -> str:
        return EnumUtils.get_all_names()

class EnumUtils:
    def __init__(self):
        pass  # equivalent to constructor in Java

    @classmethod
    def parse(cls: type['EnumUtils'], enum_type: type, s: str) -> 'enum_type':
        raise NotImplementedError("parse method not implemented")

    @classmethod
    def to_string(cls: type['EnumUtils'], enum_value: object, flags: int) -> str:
        raise NotImplementedError("to_string method not implemented")

    @classmethod
    def get_all_names(cls: type['EnumUtils']) -> str:
        raise NotImplementedError("get_all_names method not implemented")
```

Note that Python does not have a direct equivalent to Java's `@Nullable` annotation, so I did not include it in the translation. Also, the `Sound` class is assumed to be an enumeration (like Java's `enum`) and its methods are not defined here as they were in the original code.

The above Python code defines two classes: `SoundUtils` and `EnumUtils`. The `SoundUtils` class has three static methods that seem to be related to parsing, converting between strings and enum values. The `EnumUtils` class is abstract (in a sense) because its methods are not implemented here; they would need to be defined in the subclass of this class.

Please note that Python does not have an exact equivalent to Java's `@author`, so I did not include it in the translation.