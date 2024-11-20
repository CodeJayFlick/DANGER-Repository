import io

class CliIndexHasSemantics:
    BITS_USED = 1
    TABLES = [CliTypeTable.Event, CliTypeTable.Property]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexHasSemantics.BITS_USED, CliIndexHasSemantics.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexHasSemantics.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexHasSemantics.BITS_USED, CliIndexHasSemantics.TABLES)
        except Exception as e:
            raise InvalidInputException(str(e))

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexHasSemantics.BITS_USED, CliIndexHasSemantics.TABLES)
        except io.IOException as e:
            raise e

class InvalidInputException(Exception):
    pass
