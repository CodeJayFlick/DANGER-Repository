Here is the translation of the given Java interface into a Python class:

```Python
class SchemaContext:
    def __init__(self):
        self.schemas = {}

    def get_schema(self, name: str) -> 'TargetObjectSchema':
        if name in self.schemas:
            return self.schemas[name]
        else:
            raise KeyError(f"No schema by the given name {name} exists")

    def get_schema_or_null(self, name: str) -> 'TargetObjectSchema' or None:
        return self.schemas.get(name)

    def get_all_schemas(self) -> set['TargetObjectSchema']:
        return set(self.schemas.values())
```

Note that Python does not have direct support for interfaces like Java. Instead, we define a class `SchemaContext` with methods similar to the ones in the original interface. The `get_schema`, `get_schema_or_null`, and `get_all_schemas` methods are implemented using dictionaries (`self.schemas`) to store and retrieve schema objects by their names.

The type hints for Python 3.5+ have been added, indicating that these methods return a `TargetObjectSchema` object or a set of them.