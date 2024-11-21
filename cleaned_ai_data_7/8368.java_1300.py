class AbstractStaticMemberMsType:
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def emit(self, builder, bind):
        # No API for this.
        builder.append(self.name)
        self.pdb.get_type_record(self.field_type_record_number).emit(builder, bind)
        my_builder = StringBuilder()
        my_builder.append(str(self.attribute))
        my_builder.append(": ")
        builder.insert(0, str(my_builder))

class PDB:
    def __init__(self):
        pass

    def get_type_record(self, record_number):
        # This method should return the type record based on the given number
        pass


# Example usage:

pdb = PDB()
reader = PdbByteReader()  # Assuming this class exists in Python as well.
ms_type = AbstractStaticMemberMsType(pdb, reader)
builder = StringBuilder()

ms_type.emit(builder, Bind.NONE)  # Assuming this class and its NONE attribute exist in Python as well.

print(str(builder))
