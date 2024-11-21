class VectorTVList:
    def __init__(self, data_types):
        self.data_types = data_types
        self.timestamps = []
        self.indices = [[]]
        self.values = [[[] for _ in range(len(data_types))] for _ in range(ARRAY_SIZE)]
        self.bit_maps = None

    @staticmethod
    def get_primitive_arrays_by_type(type_):
        if type_ == TSDataType.TEXT:
            return [Binary() for _ in range(ARRAY_SIZE)]
        elif type_ == TSDataType.FLOAT:
            return [float() for _ in range(ARRAY_SIZE)]
        elif type_ == TSDataType.INT32:
            return [int() for _ in range(ARRAY_SIZE)]
        elif type_ == TSDataType.INT64:
            return [long() for _ in range(ARRAY_SIZE)]
        elif type_ == TSDataType.DOUBLE:
            return [float() for _ in range(ARRAY_SIZE)]
        elif type_ == TSDataType.BOOLEAN:
            return [bool() for _ in range(ARRAY_SIZE)]

    def put_vector(self, timestamp, value):
        array_index = len(self.timestamps) // ARRAY_SIZE
        element_index = len(self.timestamps) % ARRAY_SIZE

        self.timestamps.append(timestamp)
        for i, column_value in enumerate(value):
            if isinstance(column_value, list):
                self.values[i][array_index].append(column_value[element_index])
            else:
                self.values[i][array_index].append([column_value])

    def get_vector(self, index):
        array_index = index // ARRAY_SIZE
        element_index = index % ARRAY_SIZE

        return [TsPrimitiveType.get_by_type(data_types[j], value) for j, value in enumerate(self.values)]

    @staticmethod
    def clone(value):
        if isinstance(value, list):
            return [clone(v) for v in value]
        else:
            return value

    # ... other methods ...
