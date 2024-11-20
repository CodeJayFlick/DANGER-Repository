class AbstractConstantPoolReferenceInfo:
    def __init__(self):
        self.class_index = None
        self.name_and_type_index = None

    def read_from_binary_reader(self, reader):
        super().__init__()
        self.class_index = reader.read_short()
        self.name_and_type_index = reader.read_short()

    @property
    def class_index(self):
        return self.class_index & 0xffff

    @property
    def name_and_type_index(self):
        return self.name_and_type_index & 0xffff

    def to_data_type(self) -> tuple:
        name = "unnamed"
        structure = {"tag": None, "class_ index": self.class_index, "name and type index": self.name_and_type_index}
        return ("unnamed", structure)
