Here is the translation of the Java code to Python:
```
class ReferenceEndpointToReferenceTableRowMapper:
    def map(self, row_object: 'ReferenceEndpoint', data: 'Program') -> 'Reference':
        return row_object.get_reference()
```
Note that I've used type hints for the function parameters and return value, which is a feature of modern Python. The `@Override` annotation in Java has no direct equivalent in Python, as it's not necessary to explicitly indicate that you're overriding a method.

Also, keep in mind that this code assumes you have already defined classes or types called `ReferenceEndpoint`, `Program`, and `Reference` elsewhere in your Python program.