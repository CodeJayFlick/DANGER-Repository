Here is the translation of the Java code to Python:

```Python
class Location:
    def __init__(self, domain_file, function_name, entry_point):
        self.domain_file = domain_file
        self.function_name = function_name
        self.entry_point = entry_point

    def __hash__(self):
        result = 1
        if self.domain_file is not None:
            result *= hash(self.domain_file)
        if self.entry_point is not None:
            result *= hash(self.entry_point)
        if self.function_name is not None:
            result *= hash(self.function_name)
        return result

    def __eq__(self, other):
        if self == other:
            return True
        if other is None or type(other) != Location:
            return False
        if self.domain_file is None and other.domain_file is not None:
            return False
        elif self.domain_file is not None and other.domain_file is not None:
            return hash(self.domain_file) == hash(other.domain_file)
        if self.entry_point is None and other.entry_point is not None:
            return False
        elif self.entry_point is not None and other.entry_point is not None:
            return str(self.entry_point) == str(other.entry_point)
        if self.function_name is None and other.function_name is not None:
            return False
        elif self.function_name is not None and other.function_name is not None:
            return self.function_name == other.function_name
        return True

    def __str__(self):
        sb = ""
        if self.domain_file is not None:
            sb += str(self.domain_file) + ":"
        sb += self.function_name
        if self.entry_point is not None:
            sb += " (" + str(self.entry_point) + ")"
        return sb

# Example usage:
domain_file1 = 'path/to/file1'
function_name1 = 'func1'
entry_point1 = 0x12345678

location1 = Location(domain_file1, function_name1, entry_point1)

print(location1)
```

Please note that Python does not have a direct equivalent to Java's `@Override` annotation.