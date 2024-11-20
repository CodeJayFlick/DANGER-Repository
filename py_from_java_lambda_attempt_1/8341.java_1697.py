Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractDimensionedArrayMsType:
    def __init__(self, pdb, reader, record_number_size):
        self.element_record_number = None
        self.dimension_information_record_number = None
        self.name = ""

        super().__init__()
        self.element_record_number = parse_record(pdb, reader, "TYPE", record_number_size)
        self.dimension_information_record_number = parse_record(pdb, reader, "TYPE", record_number_size)
        self.name = reader.parse_string(pdb)

    def get_element_type(self):
        return pdb.get_type_record(self.element_record_number)

    def get_dimension_information_record_number(self):
        return self.dimension_information_record_number

    def get_dimension_information(self):
        return pdb.get_type_record(self.dimension_information_record_number)

    def get_name(self):
        return self.name


def parse_record(pdb, reader, record_category, size):
    # Implement the logic to parse a record
    pass


class PdbByteReader:
    def __init__(self):
        pass

    def parse_string(self, pdb):
        # Implement the logic to parse a string
        pass

    def skip_padding(self):
        # Implement the logic to skip padding
        pass


def main():
    pdb = None  # Initialize PDB object
    reader = PdbByteReader()  # Initialize PdbByteReader object
    record_number_size = 0  # Set the size of the record number

    ms_type = AbstractDimensionedArrayMsType(pdb, reader, record_number_size)

    print(ms_type.get_name())
    print(ms_type.get_element_type().get_name())
    print(ms_type.get_dimension_information().get_name())

if __name__ == "__main__":
    main()
```

Please note that the `PdbByteReader` and its methods (`parse_string`, `skip_padding`) are not implemented in this code. You would need to implement these based on your specific requirements.