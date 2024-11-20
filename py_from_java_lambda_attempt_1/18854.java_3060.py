Here is the translation of the given Java code into equivalent Python:

```Python
class IcebergTable:
    def __init__(self, metadata_location: str, id_generators: str):
        self.metadata_location = metadata_location
        self.id_generators = id_generators

    @property
    def metadata_location(self) -> str:
        return self._metadata_location

    @metadata_location.setter
    def metadata_location(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Metadata location must be a string")
        self._metadata_location = value

    @property
    def id_generators(self) -> str:
        return self._id_generators

    @id_generators.setter
    def id_generators(self, value: str):
        if not isinstance(value, str):
            raise TypeError("ID generators must be a string")
        self._id_generators = value


def of(metadata_location: str, id_generators: str) -> 'IcebergTable':
    return IcebergTable(metadata_location, id_generators)


def of(metadata_location: str, id_generators: str, contents_id: str) -> 'IcebergTable':
    return IcebergTable(metadata_location, id_generators)
```

Note that Python does not have direct equivalents for Java's `@Schema`, `@Value.Immutable`, `@JsonSerialize`, and `@JsonDeserialize` annotations. These are typically handled by serialization libraries such as JSON-B or Pydantic.

Also note that the `getMetadataLocation()` method in the original code is abstract, which means it must be implemented by any subclass of `IcebergTable`. In Python, this would not work directly because methods cannot be declared as abstract like they can in Java. Instead, you could use a property (like I did above) or create an interface that defines the method and has subclasses implement it.

Finally, note that the original code uses Java's type annotations (`@JsonTypeName("ICEBERG_TABLE")`, etc.) to specify serialization details. Python does not have direct equivalents for these either; you would typically use a library like JSON-B or Pydantic to handle this kind of thing.