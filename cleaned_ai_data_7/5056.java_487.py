import io

class CliIndexTypeOrMethodDef:
    BITS_USED = 1
    TABLES = [CliTypeDefTable(), CliMethodDefTable()]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexTypeOrMethodDef.BITS_USED, CliIndexTypeOrMethodDef.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexTypeOrMethodDef.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexTypeOrMethodDef.BITS_USED, CliIndexTypeOrMethodDef.TABLES)
        except InvalidInputException as e:
            raise

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexTypeOrMethodDef.BITS_USED, CliIndexTypeOrMethodDef.TABLES)
        except IOError as e:
            raise


class CliTypeDefTable:
    pass

class CliMethodDefTable:
    pass
