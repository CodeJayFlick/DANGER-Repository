class InterfaceMsType:
    PDB_ID = 0x1519
    TYPE_STRING = "interface"

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.count = reader.parse_unsigned_short_val()
        self.property = MsProperty(reader)
        self.field_descriptor_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.derived_from_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.v_shape_table_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder, bind):
        my_builder = StringBuilder()
        my_builder.append(self.TYPE_STRING)
        my_builder.append(" ")
        if hasattr(self, "name"):
            my_builder.append(self.name)
        else:
            my_builder.append("")
        if hasattr(self, "mangled_name"):
            my_builder.append("<")
            my_builder.append(str(self.count))
            my_builder.append(",")
            my_builder.append(str(self.property))
            my_builder.append(">")
        elif hasattr(self, "property"):
            my_builder.append("<")
            my_builder.append(str(self.count))
            my_builder.append(",")
            my_builder.append(str(self.property))
            my_builder.append(">")

        if hasattr(self, "field_descriptor_list_type"):
            my_builder.append(str(self.field_descriptor_list_type))

        builder.insert(0, str(my_builder))

    def get_type_string(self):
        return self.TYPE_STRING


class MsProperty:
    pass


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # todo: implement this method
        pass


class StringBuilder:
    def __init__(self):
        self.builder = ""

    def append(self, string):
        self.builder += str(string)

    def insert(self, index, string):
        self.builder = str(string) + self.builder

    def get_string(self):
        return self.builder


# todo: implement the rest of the classes
