Here is the translation of the Java code into equivalent Python:

```Python
class DataDesc:
    def __init__(self, shape, data_type=None, name=None):
        self.name = name
        self.shape = shape
        self.data_type = data_type if data_type else 'float32'

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def shape(self):
        return self._shape

    @shape.setter
    def shape(self, value):
        self._shape = value

    @property
    def data_type(self):
        return self._data_type

    @data_type.setter
    def data_type(self, value):
        self._data_type = value

    def __str__(self):
        return f"{self.name} shape: {self.shape}, data type: {self.data_type}"
```

This Python code defines a `DataDesc` class with similar properties and methods as the Java original. The constructor takes three parameters: `shape`, `data_type`, and `name`. If no `data_type` is provided, it defaults to `'float32'`.