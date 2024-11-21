Here is the equivalent Python code:

```Python
class ReferenceEndpointToProgramLocationTableRowMapper:
    def map(self, row_object: 'ReferenceEndpoint', data: 'Program') -> 'ProgramLocation':
        return ProgramLocation(data, row_object.get_address())

# Note that in Python, we don't need to define classes for every type like Java does.
```

This code defines a class `ReferenceEndpointToProgramLocationTableRowMapper` with one method `map`. The `map` method takes three parameters: `row_object`, which is an instance of the `ReferenceEndpoint` class; `data`, which is an instance of the `Program` class; and `sp`, which seems to be unused in this code. It returns a new instance of the `ProgramLocation` class, initialized with the given data and address.

Please note that Python does not have direct equivalent for Java's generics system (type parameters). The type hints are used here only as documentation, they do not provide any compile-time or runtime checks.