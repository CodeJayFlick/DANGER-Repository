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
