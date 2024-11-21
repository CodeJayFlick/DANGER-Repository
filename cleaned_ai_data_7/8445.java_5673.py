class MatrixMsType:
    PDB_ID = 0x151c

    def __init__(self):
        self.element_type_record_number = None
        self.num_rows = None
        self.num_columns = None
        self.major_stride = None
        self.row_major = False
        self.size = None
        self.name = None

    @staticmethod
    def from_pdb(pdb, reader):
        matrix_ms_type = MatrixMsType()
        matrix_ms_type.element_type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        matrix_ms_type.num_rows = reader.read_unsigned_int_val()
        matrix_ms_type.num_columns = reader.read_unsigned_int_val()
        matrix_ms_type.major_stride = reader.read_unsigned_int_val()
        attribute = reader.read_unsigned_byte_val()
        matrix_ms_type.row_major = (attribute & 0x01) == 0x01
        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        matrix_ms_type.size = numeric.get_integrals()[0]
        matrix_ms_type.name = reader.read_string(pdb, 'StringNt')
        return matrix_ms_type

    def get_pdb_id(self):
        return self.PDB_ID

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    def get_num_rows(self):
        return self.num_rows

    def get_num_columns(self):
        return self.num_columns

    def is_row_major(self):
        return self.row_major

    def get_major_stride(self):
        return self.major_stride

    @staticmethod
    def emit(builder, bind):
        builder.append(f"matrix: {self.name}[{'row' if self.row_major else 'column'}<{pdb.get_type_record(self.element_type_record_number).toString()}> {self.num_rows}][{'row' if not self.row_major else 'column'}<{pdb.get_type_record(self.element_type_record_number).toString()}> {self.num_columns}]")
