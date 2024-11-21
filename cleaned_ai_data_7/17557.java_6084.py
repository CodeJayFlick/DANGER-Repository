class LayerPointReaderBackedSingleColumnRow:
    def __init__(self, layer_point_reader):
        self.layer_point_reader = layer_point_reader

    def get_time(self) -> int:
        return self.layer_point_reader.current_time()

    def get_int(self, column_index: int) -> int:
        return self.layer_point_reader.current_int()

    def get_long(self, column_index: int) -> int:
        return self.layer_point_reader.current_long()

    def get_float(self, column_index: int) -> float:
        return self.layer_point_reader.current_float()

    def get_double(self, column_index: int) -> float:
        return self.layer_point_reader.current_double()

    def get_boolean(self, column_index: int) -> bool:
        return self.layer_point_reader.current_boolean()

    def get_binary(self, column_index: int) -> bytes:
        return self.layer_point_reader.current_binary().get_value()

    def get_string(self, column_index: int) -> str:
        return self.layer_point_reader.current_binary().get_string_value()

    def get_data_type(self, column_index: int) -> 'TSDataType':
        # Assuming TSDataType is an enum in Python
        return self.layer_point_reader.get_data_type()

    def is_null(self, column_index: int) -> bool:
        return False

    def size(self) -> int:
        return 1
