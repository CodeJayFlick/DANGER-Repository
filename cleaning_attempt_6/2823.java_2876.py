class SchemaBuilder:
    def __init__(self):
        self.version = 0
        self.key_field_name = "Key"
        self.key_field_class = type("LongField", (), {})
        self.field_names = []
        self.field_classes = []

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    def key_field(self, name: str, cls) -> 'SchemaBuilder':
        self.key_field_name = name
        self.key_field_class = cls
        return self

    def field(self, name: str, cls) -> 'SchemaBuilder':
        self.field_names.append(name)
        self.field_classes.append(cls)
        return self

    @property
    def field_count(self):
        return len(self.field_names)

    def build(self) -> dict:
        return {
            "version": self.version,
            "key_field_class": type.__name__,
            "key_field_name": self.key_field_name,
            "field_classes": [cls.__name__ for cls in self.field_classes],
            "field_names": self.field_names
        }
