import io

class CliIndexCustomAttributeType:
    BITS_USED = 3
    TABLES = [None, None, "MethodDef", "MemberRef"]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexCustomAttributeType.BITS_USED, CliIndexCustomAttributeType.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexCustomAttributeType.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexCustomAttributeType.BITS_USED, CliIndexCustomAttributeType.TABLES)
        except Exception as e:
            raise InvalidInputException(str(e))

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexCustomAttributeType.BITS_USED, CliIndexCustomAttributeType.TABLES)
        except io.IOException as e:
            raise e

class InvalidInputException(Exception):
    pass
