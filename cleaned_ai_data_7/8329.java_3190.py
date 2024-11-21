class AbstractArrayMsType:
    def __init__(self):
        self.element_type_record_number = None
        self.index_type_record_number = None
        self.size = 0
        self.name = ""
        self.stride = -1

    @property
    def element_type_record_number(self):
        return self._element_type_record_number

    @element_type_record_number.setter
    def element_type_record_number(self, value):
        self._element_type_record_number = value

    @property
    def index_type_record_number(self):
        return self._index_type_record_number

    @index_type_record_number.setter
    def index_type_record_number(self, value):
        self._index_type_record_number = value

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Size must be a non-negative integer")
        self._size = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        self._name = value

    @property
    def stride(self):
        return self._stride

    @stride.setter
    def stride(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Stride must be a non-negative integer")
        self._stride = value

    def __init__(self, pdb, reader, record_number_size, str_type, read_stride):
        super().__init__()
        self.element_type_record_number = RecordNumber.parse(pdb, reader, "TYPE", record_number_size)
        self.index_type_record_number = RecordNumber.parse(pdb, reader, "TYPE", record_number_size)
        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        self.size = numeric.get_integral()
        if read_stride:
            self.stride = reader.parse_unsigned_int_val()
        else:
            self.stride = -1
        self.name = reader.parse_string(pdb, str_type)
        reader.skip_padding()

    def get_size(self):
        return self.size

    def get_element_type_record_number(self):
        return self.element_type_record_number

    def get_index_type_record_number(self):
        return self.index_type_record_number

    def get_element_type(self):
        return pdb.get_type_record(self.element_type_record_number)

    def get_index_type(self):
        return pdb.get_type_record(self.index_type_record_number)

    def get_name(self):
        return self.name

    def emit(self, builder, bind):
        if bind.ordinal() < Bind.ARRAY.ordinal():
            builder.insert(0, "(")
            builder.append(")")
        my_builder = StringBuilder()
        my_builder.append("<")
        my_builder.append(pdb.get_type_record(self.index_type_record_number))
        my_builder.append(">")

        builder.append("[")
        builder.append(str(self.size))
        builder.append(my_builder)
        builder.append("]")

        self.get_element_type().emit(builder, Bind.ARRAY)

class PdbException(Exception):
    pass

class Numeric:
    def __init__(self, reader):
        self.reader = reader
        self.is_integral = True

    @property
    def is_integral(self):
        return self._is_integral

    @is_integral.setter
    def is_integral(self, value):
        if not isinstance(value, bool):
            raise TypeError("Is integral must be a boolean")
        self._is_integral = value

    def get_integral(self):
        # Implement this method to parse the numeric data from reader.
        pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, record_number_size):
        # Implement this method to parse the record number from pdb and reader.
        pass

class StringBuilder:
    def __init__(self):
        self._builder = ""

    @property
    def builder(self):
        return self._builder

    @builder.setter
    def builder(self, value):
        if not isinstance(value, str):
            raise TypeError("Builder must be a string")
        self._builder = value

    def insert(self, index, s):
        # Implement this method to insert the given string at the specified position.
        pass

    def append(self, s):
        # Implement this method to append the given string to the end of the builder.
        pass
