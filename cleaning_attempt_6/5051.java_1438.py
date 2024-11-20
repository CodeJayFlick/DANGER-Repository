import io

class CliIndexMemberForwarded:
    BITS_USED = 1
    TABLES = [CliTypeTable.FIELD, CliTypeTable.METHOD_DEF]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexMemberForwarded.BITS_USED, CliIndexMemberForwarded.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexMemberForwarded.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexMemberForwarded.BITS_USED, CliIndexMemberForwarded.TABLES)
        except Exception as e:
            raise InvalidInputException(str(e))

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexMemberForwarded.BITS_USED, CliIndexMemberForwarded.TABLES)
        except io.IOException as e:
            raise
