Here is the translation of the Java code to Python:
```
class ReferenceEndpointToAddressTableRowMapper:
    def map(self, row_object: 'ReferenceEndpoint', data: 'Program') -> 'int':
        return row_object.get_address()
```
Note that I've kept the type hints for clarity and compatibility with modern Python syntax. However, if you're using an older version of Python or prefer not to use type hints, you can simply remove them:
```
class ReferenceEndpointToAddressTableRowMapper:
    def map(self, row_object, data):
        return row_object.get_address()
```