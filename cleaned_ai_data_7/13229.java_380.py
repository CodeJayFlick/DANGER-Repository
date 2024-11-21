class AnnotationJava:
    def __init__(self):
        self.type_index = 0
        self.number_of_element_value_pairs = 0
        self.element_value_pairs = []

    def read_from_binary(self, reader):
        self.type_index = reader.read_short()
        self.number_of_element_value_pairs = reader.read_short()
        self.element_value_pairs = [AnnotationElementValuePair(reader) for _ in range(self.get_number_of_element_value_pairs())]

    @property
    def type_index(self):
        return self.type_index & 0xffff

    @property
    def number_of_element_value_pairs(self):
        return self.number_of_element_value_pairs & 0xffff

    @property
    def element_value_pairs(self):
        return self.element_value_pairs


class AnnotationElementValuePair:
    def __init__(self, reader):
        self.element_name_index = reader.read_short()
        # Assuming 'value' is some kind of object that can be read from the binary file
        self.value = None

    @property
    def element_name_index(self):
        return self.element_name_index & 0xffff


def to_data_type(self) -> str:
    name = f"annotation|{self.number_of_element_value_pairs}|"
    structure = {"name": name, "fields": []}
    
    structure["fields"].append({"type": "WORD", "name": "type_index"})
    structure["fields"].append({"type": "WORD", "name": "num_element_value_pairs"})

    for i in range(len(self.element_value_pairs)):
        field = {"type": self.element_value_pairs[i].to_data_type(), "name": f"element_value_pair_{i}"}
        structure["fields"].append(field)

    return structure
