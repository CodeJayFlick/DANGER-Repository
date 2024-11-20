class Undefined:
    def __init__(self, name):
        self.name = name

undefined_types = []

def get.undefined_types():
    if not undefined_types:
        undefined_types = [Undefined("Undefined1"), Undefined("Undefined2"),
                            Undefined("Undefined3"), Undefined("Undefined4"),
                            Undefined("Undefined5"), Undefined("Undefined6"),
                            Undefined("Undefined7"), Undefined("Undefined8")]
    return undefined_types

def get_undefined_data_type(size):
    if size < 1:
        return DefaultDataType()
    elif size > 8:
        return ArrayDataType(Undefined("Undefined1"), size, 1)
    else:
        return undefined_types[size - 1]

def get.undefined_data_types():
    return [dt.clone() for dt in get.undefined_types()]

def is_undefined(data_type):
    if isinstance(data_type, DefaultDataType):
        return True
    elif isinstance(data_type, Undefined):
        return True
    else:
        return is_undefined_array(data_type)

def is_undefined_array(data_type):
    if not isinstance(data_type, Array):
        return False
    base_type = data_type.get_data_type()
    return isinstance(base_type, (Undefined, DefaultDataType))

class DefaultDataType:
    def __init__(self):
        pass

class Undefined(DataType):
    def __init__(self, name):
        super().__init__()
        self.name = name

class ArrayDataType(DataType):
    def __init__(self, base_type, size, array_size):
        super().__init__()
        self.base_type = base_type
        self.size = size
        self.array_size = array_size

class DataType:
    pass
