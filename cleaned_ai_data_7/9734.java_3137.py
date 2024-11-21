class ColumnTypeMapper:
    def __init__(self):
        pass

    @staticmethod
    def from_source_to_destination(source_type: type, destination_type: type) -> 'ColumnTypeMapper':
        return ColumnTypeMapper(source_type, destination_type)

    def convert(self, value):
        raise NotImplementedError("convert method must be implemented by subclass")

    @property
    def source_type(self) -> type:
        return self._source_type

    @source_type.setter
    def source_type(self, value: type):
        if not isinstance(value, type):
            raise TypeError("Source type must be a type")
        self._source_type = value

    @property
    def destination_type(self) -> type:
        return self._destination_type

    @destination_type.setter
    def destination_type(self, value: type):
        if not isinstance(value, type):
            raise TypeError("Destination type must be a type")
        self._destination_type = value

    def __eq__(self, other):
        if not isinstance(other, ColumnTypeMapper):
            return False
        return (isinstance(other, type) and 
                self.source_type == other.source_type and 
                self.destination_type == other.destination_type)

    def __hash__(self):
        return hash((self.source_type, self.destination_type))

def find_source_type(cls: type) -> type:
    for base in cls.__bases__:
        if isinstance(base, ColumnTypeMapper):
            return base._source_type
    raise ValueError("No source type found")

def find_destination_type(cls: type) -> type:
    for base in cls.__bases__:
        if isinstance(base, ColumnTypeMapper):
            return base._destination_type
    raise ValueError("No destination type found")
