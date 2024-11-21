class AbstractNestedTypeMsType:
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def nested_type_definition_record_number(self):
        return self._nested_type_definition_record_number

    @nested_type_definition_record_number.setter
    def nested_type_definition_record_number(self, value):
        self._nested_type_definition_record_number = value

    def emit(self, builder, bind):
        # No API for this.
        builder.append(self.name)
        pdb.get_type_record(self.nested_type_definition_record_number).emit(builder, bind)

class Pdb:
    def get_type_record(self, record_number):
        pass
