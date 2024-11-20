Here is the translation of the given Java code into Python:

```Python
class ProgramLocationColumnTypeMapper:
    def convert(self, program_location: 'ProgramLocation') -> 'Address':
        return program_location.get_address()

# Note that in Python, we don't need to define a class for every type like in Java.
```

In this translation, I have used the same structure as the original code. The `convert` method takes an instance of `ProgramLocation`, calls its `get_address` method and returns the result which is expected to be an instance of `Address`.