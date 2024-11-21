class FieldIDItem:
    def __init__(self):
        self.class_index = None
        self.type_index = None
        self.name_index = None

    @classmethod
    def from_reader(cls, reader):
        try:
            self.class_index = reader.read_short()
            self.type_index = reader.read_short()
            self.name_index = reader.read_int()
        except Exception as e:
            print(f"Error: {e}")

    def get_class_index(self):
        return self.class_index

    def get_type_index(self):
        return self.type_index

    def get_name_index(self):
        return self.name_index
