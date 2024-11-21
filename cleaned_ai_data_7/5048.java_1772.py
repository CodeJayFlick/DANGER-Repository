class CliIndexHasFieldMarshall:
    BITS_USED = 1
    TABLES = [CliTypeTable.FIELD, CliTypeTable.PARAM]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexHasFieldMarshall.BITS_USED, CliIndexHasFieldMarshall.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexHasFieldMarshall.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexHasFieldMarshall.BITS_USED, CliIndexHasFieldMarshall.TABLES)
        except Exception as e:
            raise InvalidInputException(str(e))

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexHasFieldMarshell.BITS_USED, CliIndexHasFieldMarshall.TABLES)
        except Exception as e:
            raise IOException(str(e))
