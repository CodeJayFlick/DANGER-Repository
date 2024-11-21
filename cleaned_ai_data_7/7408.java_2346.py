class ISO9660SetTerminator:
    def __init__(self):
        self.end_volume_index = None

    def set_reader(self, reader):
        super().__init__()
        try:
            self.end_volume_index = reader.get_pointer_index()
        except Exception as e:
            print(f"An error occurred: {e}")

    @property
    def end_volume_index(self):
        return self._end_volume_index

    @end_volume_index.setter
    def end_volume_index(self, value):
        self._end_volume_index = value

    def to_data_type(self) -> dict:
        data_type = {"ISO9600SetTerminator": 0}
        data_type["Type"] = "Volume Descriptor Type"
        identifier_length = len(super().get_identifier())
        data_type["Identifier"] = [f"Byte {i}" for i in range(identifier_length)]
        data_type["Version"] = "Volume Descriptor Version"

        return data_type
