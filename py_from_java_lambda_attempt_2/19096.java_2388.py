Here is the translation of the given Java interface into a Python class:

```Python
class TxConnectionConfig:
    def __init__(self):
        self._catalog = None
        self._schema = None

    @property
    def catalog(self):
        return self._catalog

    @catalog.setter
    def catalog(self, value):
        if not isinstance(value, str) or len(value) > 0:
            raise ValueError("Catalog must be a non-empty string")
        self._catalog = value

    def with_catalog(self, catalog: str) -> 'TxConnectionConfig':
        self.catalog = catalog
        return self

    @property
    def schema(self):
        return self._schema

    @schema.setter
    def schema(self, value):
        if not isinstance(value, str) or len(value) > 0:
            raise ValueError("Schema must be a non-empty string")
        self._schema = value

    def with_schema(self, schema: str) -> 'TxConnectionConfig':
        self.schema = schema
        return self
```

This Python class `TxConnectionConfig` has the same methods and properties as the Java interface. The main difference is that in Python we use a constructor (`__init__`) to initialize instance variables instead of using a separate method for initialization, like in Java.