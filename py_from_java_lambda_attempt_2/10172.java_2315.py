Here is the translation of the Java code into equivalent Python:

```Python
class ConstraintData:
    def __init__(self, mappings):
        self.map = {k: v for k, v in mappings.items()}

    def get_string(self, name):
        return self.get_value(name, "string")

    def has_value(self, name):
        return name in self.map

    def get_int(self, name):
        value = self.get_value(name, "int")
        try:
            return int(value)
        except ValueError:
            raise Exception(f"Expected int value for attribute '{name}', but was '{value}'")

    def get_long(self, name):
        value = self.get_value(name, "long")
        try:
            return long(int(float(value)))
        except ValueError:
            raise Exception(f"Expected long value for attribute '{name}', but was '{value}'")

    def get_boolean(self, name):
        value = self.get_value(name, "boolean").lower()
        if value == "true":
            return True
        elif value == "false":
            return False
        else:
            raise Exception(f"Expected boolean value for attribute '{name}', but was '{value}'")

    def get_float(self, name):
        try:
            return float(self.get_value(name, "float"))
        except ValueError:
            raise Exception(f"Expected float value for attribute '{name}', but was '{self.get_value(name, 'float')}'")

    def get_double(self, name):
        try:
            return float(self.get_value(name, "double"))
        except ValueError:
            raise Exception(f"Expected double value for attribute '{name}', but was '{self.get_value(name, 'double')}'")

    def get_value(self, name, type):
        if not self.has_value(name):
            raise Exception(f"Missing {type} value for attribute '{name}'")
        return self.map[name]
```

Please note that Python does not have direct equivalents of Java's `HashMap` and `XmlAttributeException`. The equivalent data structure in Python is a dictionary (`{}`), which maps keys to values. For exceptions, you can use the built-in `Exception` class or create your own custom exception classes as needed.