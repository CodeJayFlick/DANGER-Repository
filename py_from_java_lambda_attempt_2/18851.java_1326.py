Here is the translation of the given Java code into Python:

```Python
class ContentsKey:
    ZERO_BYTE = '\u0000'
    ZERO_BYTE_STRING = chr(ZERO_BYTE)

    def __init__(self):
        self._elements = []

    @property
    def elements(self):
        return self._elements

    @elements.setter
    def elements(self, value):
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise ValueError("Elements must be a non-empty list of strings")
        self._elements = value

    def get_namespace(self):
        return Namespace(*self.elements[:-1])

    @property
    def name(self):
        if not self.elements:
            return None
        return self.elements[-1]

    @classmethod
    def from_namespace_name(cls, namespace: 'Namespace', name: str) -> 'ContentsKey':
        builder = ImmutableContentsKeyBuilder()
        if namespace and len(namespace) > 0:
            builder.add_elements(list(namespace))
        return builder.add_element(name).build()

    @classmethod
    def from_elements(cls, *elements):
        Objects.requireNonNull(elements)
        return cls(ImmutableContentsKeyBuilder().add_elements(list(map(str, elements))).build())

    @classmethod
    def of_json(cls, data: dict) -> 'ContentsKey':
        if not isinstance(data, dict) or "elements" not in data:
            raise ValueError("Invalid JSON")
        Objects.requireNonNull(data["elements"])
        return cls(ImmutableContentsKeyBuilder().add_elements(list(map(str, data["elements"]))).build())

    def validate(self):
        for element in self.elements:
            if not element:
                raise ValueError("An object key must not contain a null element.")
            if ZERO_BYTE_STRING in element:
                raise ValueError("An object key must not contain a zero byte.")

    @classmethod
    def from_path_string(cls, encoded: str) -> 'ContentsKey':
        elements = list(map(lambda x: x.replace(ZERO_BYTE, '.'), encoded.split('.')))
        return cls(*elements)

    def to_path_string(self):
        return ".".join(element.replace('.', ZERO_BYTE) for element in self.elements)

    def __str__(self):
        return ".".join(str(x) for x in self.elements)
```

Please note that this is a direct translation of the given Java code into Python, and it may not be perfect or idiomatic Python.