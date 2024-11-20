class CliIndexResolutionScope:
    BITS_USED = 2
    TABLES = [CliTypeTable.Module, CliTypeTable.ModuleRef, CliTypeTable.AssemblyRef, CliTypeTable.TypeRef]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexResolutionScope.BITS_USED, CliIndexResolutionScope.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexResolutionScope.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexResolutionScope.BITS_USED, CliIndexResolutionScope.TABLES)
        except Exception as e:
            raise InvalidInputException(str(e))

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexResolutionScope.BITS_USED, CliIndexResolutionScope.TABLES)
        except Exception as e:
            raise IOException(str(e))
