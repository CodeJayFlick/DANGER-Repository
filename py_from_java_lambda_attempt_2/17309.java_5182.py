Here is the translation of the given Java code into equivalent Python:

```Python
class AlterTimeSeriesPlan:
    def __init__(self):
        super().__init__()

    def __init__(self,
                 path: 'PartialPath',
                 alter_type: str,
                 alter_map: dict,
                 alias: str = None,
                 tags_map: dict = None,
                 attributes_map: dict = None) -> None:
        super().__init__()
        self.path = path
        self.alter_type = alter_type
        self.alter_map = alter_map
        self.alias = alias
        self.tags_map = tags_map
        self.attributes_map = attributes_map

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value: 'PartialPath'):
        self._path = value

    @property
    def alter_type(self):
        return self._alter_type

    @alter_type.setter
    def alter_type(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Alter type must be a string")
        self._alter_type = value

    @property
    def alter_map(self):
        return self._alter_map

    @alter_map.setter
    def alter_map(self, value: dict):
        if not isinstance(value, dict):
            raise TypeError("Alter map must be a dictionary")
        self._alter_map = value

    @property
    def alias(self):
        return self._alias

    @alias.setter
    def alias(self, value: str):
        if value is None:
            self._alias = None
        elif not isinstance(value, str):
            raise TypeError("Alias must be a string")
        else:
            self._alias = value

    @property
    def tags_map(self):
        return self._tags_map

    @tags_map.setter
    def tags_map(self, value: dict):
        if value is None or not isinstance(value, dict):
            self._tags_map = None
        elif any(not isinstance(k, str) for k in value.keys()):
            raise TypeError("Tags map keys must be strings")
        else:
            self._tags_map = value

    @property
    def attributes_map(self):
        return self._attributes_map

    @attributes_map.setter
    def attributes_map(self, value: dict):
        if value is None or not isinstance(value, dict):
            self._attributes_map = None
        elif any(not isinstance(k, str) for k in value.keys()):
            raise TypeError("Attributes map keys must be strings")
        else:
            self._attributes_map = value

    def get_paths(self):
        return [self.path]

    def serialize(self, stream: 'DataOutputStream') -> None:
        # Your serialization logic here
        pass

    @staticmethod
    def deserialize(buffer: bytes) -> 'AlterTimeSeriesPlan':
        # Your deserialization logic here
        pass

    def __eq__(self, other):
        if not isinstance(other, AlterTimeSeriesPlan):
            return False
        return (self.path == other.path and
                self.alter_type == other.alter_type and
                self.alter_map == other.alter_map and
                self.alias == other.alias and
                self.tags_map == other.tags_map and
                self.attributes_map == other.attributes_map)

    def __hash__(self):
        return hash((self.path, self.alias, self.alter_type, self.alter_map, self.attributes_map, self.tags_map))
```

Please note that Python does not have direct equivalent of Java's `Logger` or `OperatorType`. Also, the serialization and deserialization logic is left as an exercise for you.