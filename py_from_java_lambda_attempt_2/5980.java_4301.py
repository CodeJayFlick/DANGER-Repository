Here is the equivalent Python code:

```Python
class ReferenceEndpointToFunctionTableRowMapper:
    def map(self, row_object: 'ReferenceEndpoint', data: 'Program') -> 'Function':
        return next((f for f in data.get_functions() if f.contains(row_object.address)), None)
```

Note that this translation is not a direct equivalent of the Java code. Python does not have built-in support for generics like Java, so we've omitted those parts. Also, Python's type hinting system (`-> 'Function'`) serves a similar purpose to Java's generic types.

The `map` method in the original Java code takes three parameters: `rowObject`, `data`, and `sp`. In the translation, I have removed `sp` as it is not used anywhere. The `map` function returns a `Function` object if found; otherwise, it returns None.