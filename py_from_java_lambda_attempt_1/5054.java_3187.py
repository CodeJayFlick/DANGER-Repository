Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the `CliTypeTable` and `CliCodedIndexUtils` classes, since they are not provided in the original Java code. In Python, we don't have a direct equivalent of Java's static methods, so I used class-level functions (i.e., instance methods with no self parameter) to mimic their behavior.

Also, I replaced the `throws IOException` and `throws InvalidInputException` clauses with try-except blocks in the corresponding method implementations. This is because Python does not have a built-in equivalent of Java's checked exceptions mechanism.