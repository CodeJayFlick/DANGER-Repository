class CliIndexHasCustomAttribute:
    BITS_USED = 5
    TABLES = [CliTypeTable.MethodDef, CliTypeTable.Field, CliTypeTable.TypeRef,
              CliTypeTable.TypeDef, CliTypeTable.Param, CliTypeTable.InterfaceImpl,
              CliTypeTable.MemberRef, CliTypeTable.Module, None, CliTypeTable.Property,
              CliTypeTable.Event, CliTypeTable.StandAloneSig, CliTypeTable.ModuleRef,
              CliTypeTable.TypeSpec, CliTypeTable.Assembly, CliTypeTable.AssemblyRef,
              CliTypeTable.File, CliTypeTable.ExportedType, CliTypeTable.ManifestResource]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexHasCustomAttribute.BITS_USED, CliIndexHasCustomAttribute.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexHasCustomAttribute.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexHasCustomAttribute.BITS_USED, CliIndexHasCustomAttribute.TABLES)
        except Exception as e:
            raise InvalidInputException(str(e))

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexHasCustomAttribute.BITS_USED, CliIndexHasCustomAttribute.TABLES)
        except Exception as e:
            raise IOException(str(e))
