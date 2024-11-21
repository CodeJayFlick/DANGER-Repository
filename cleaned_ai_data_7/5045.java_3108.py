import io

class CliIndexHasConstant:
    BITS_USED = 2
    TABLES = [CliTypeTable.FIELD, CliTypeTable.PARAM, CliTypeTable.PROPERTY]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexHasConstant.BITS_USED, CliIndexHasConstant.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexHasConstant.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexHasConstant.BITS_USED, CliIndexHasConstant.TABLES)
        except Exception as e:
            raise InvalidInputException(str(e))

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexHasConstant.BITS_USED, CliIndexHasConstant.TABLES)
        except io.IOException as e:
            raise e

class InvalidInputException(Exception):
    pass
