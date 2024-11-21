class StringEvent:
    def __init__(self, string_data_type: 'DataType', address: 'Address', length: int):
        self.string_data_type = string_data_type
        self.address = address
        self.length = length

    @abstractmethod
    def process(self, model: 'StringTableModel', options: 'StringTableOptions'):
        pass

    def find_row_slow_way(self, model) -> 'FoundString':
        model_data = model.get_model_data()
        for row in range(len(model_data)):
            string = model_data[row]
            if self.overlaps(string):
                return string
        return None

    @staticmethod
    def get_max_address(addr1: 'Address', addr2: 'Address') -> 'Address':
        if addr1 > addr2:
            return addr1
        return addr2

    @staticmethod
    def get_min_address(addr1: 'Address', addr2: 'Address') -> 'Address':
        if addr1 < addr2:
            return addr1
        return addr2

    def overlaps(self, string) -> bool:
        other_address = string.get_address()
        result = self.address - other_address
        if result == 0:
            return True
        elif result < 0:
            return other_address - self.address < self.length
        else:
            return self.address - other_address < string.get_length()

    @staticmethod
    def subtract(big_address: 'Address', small_address: 'Address') -> int:
        if big_address.get_address_space() != small_address.get_address_space():
            return int('inf')
        diff = big_address - small_address
        if diff > int('inf'):
            return int('inf')
        else:
            return int(diff)
