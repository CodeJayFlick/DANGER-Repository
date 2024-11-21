Here is the translation of the Java code into Python:

```Python
class ExternalPath:
    DELIMITER_STRING = "::"

    def __init__(self, *strings):
        for string in strings:
            if not isinstance(string, str) or len(string) <= 0:
                raise ValueError("An external path cannot contain a null or empty string.")
        
        if len(strings) < 2:
            raise ValueError("An external path must specify a library name and a label.")

        self.strings = list(strings)

    def get_library_name(self):
        return self.strings[0]

    def get_name(self):
        return self.strings[-1]

    def get_path_elements(self):
        # FIXME Make the array that is returned immutable instead.
        return self.strings[:]

    def __str__(self):
        last_index = len(self.strings) - 1
        buffer = ""
        for i in range(len(self.strings)):
            buffer += str(self.strings[i])
            if i < last_index:
                buffer += self.DELIMITER_STRING
        return buffer

# Example usage:
path = ExternalPath("lib", "func", "label")
print(path)  # Output: lib::func::label
```

Note that Python does not have a direct equivalent to Java's `String[]` or `System.arraycopy()`, so I used the built-in list and slicing operations instead. Also, Python has no concept of an immutable array like in Java; however, you can achieve similar behavior by returning a copy of the original list using slicing (`self.strings[:]`).