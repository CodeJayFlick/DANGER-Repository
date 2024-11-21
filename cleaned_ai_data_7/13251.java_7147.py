class NestMembersAttribute:
    def __init__(self):
        self.number_of_classes = None
        self.classes = []

    def read_from_binary_reader(self, reader):
        self.super_init(reader)
        self.number_of_classes = reader.read_short()
        for _ in range(self.get_number_of_classes()):
            self.classes.append(reader.read_short())

    def get_number_of_classes(self):
        return self.number_of_classes & 0xffff

    def get_class_entry(self, i):
        return self.classes[i] & 0xffff

    def to_data_type(self):
        structure = StructureDataType("NestMembers_attribute")
        structure.add(WORD, "number_of_classes", None)
        for i in range(len(self.classes)):
            structure.add(WORD, f"classes{i}", None)
        return structure
