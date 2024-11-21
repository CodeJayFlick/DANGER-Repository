Here is the equivalent Python code:

```Python
class StringStringable:
    SHORT_NAME = "STR"
    EMPTY_STRING = ""

    def __init__(self):
        self.value = None

    def __init__(self, string=None):
        super().__init__()
        if string is not None:
            self.value = string

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, v):
        self._value = v

    def get_string(self):
        return self.value

    def get_display_string(self):
        if self.value is not None:
            return self.value
        else:
            return EMPTY_STRING

    def do_convert_to_string(self, program=None):
        if self.value is None:
            return EMPTY_STRING
        elif program is not None:
            # This method seems to be unused in the original code.
            pass
        return self.value

    def do_restore_from_string(self, string, program=None):
        if string == EMPTY_STRING:
            self.value = None
        else:
            self.value = string

    def __hash__(self):
        prime = 31
        result = 1
        if self.value is not None:
            result *= prime + hash(self.value)
        return result

    def __eq__(self, other):
        if self == other:  # Check for same object reference.
            return True
        elif isinstance(other, StringStringable) and self.__class__ == other.__class__:
            return SystemUtilities.isEqual(self.value, other.value)
        else:
            return False

# You can use the class like this:

ss = StringStringable("Hello")
print(ss.get_string())  # prints: Hello
print(ss.get_display_string())  # prints: Hello

ss2 = StringStringable()
print(ss2.get_string())  # prints: None
print(ss2.get_display_string())  # prints: ""

# Note that the SystemUtilities.isEqual method is not defined in this code.
```

This Python class `StringStringable` has similar methods and properties as the original Java class. It uses Python's built-in features like property decorators, type checking with isinstance(), etc., to achieve the same functionality.