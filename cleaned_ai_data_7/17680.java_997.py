class TVList:
    def __init__(self):
        self.timestamps = []
        self.size = 0
        self.min_time = float('inf')
        self.reference_count = AtomicInteger(1)

    @staticmethod
    def new_list(data_type):
        if data_type == 'TEXT':
            return BinaryTVList()
        elif data_type == 'FLOAT':
            return FloatTVList()
        # Add more types as needed

    @staticmethod
    def tv_list_array_mem_size(type):
        size = 0
        size += PrimitiveArrayManager.ARRAY_SIZE * 8
        if type.get_data_type_size() is not None:
            size += PrimitiveArrayManager.ARRAY_SIZE * type.get_data_type_size()
        return size

    # Add more methods as needed


class BinaryTVList(TVList):
    pass


class FloatTVList(TVList):
    pass


# Define other TV list classes for different data types
