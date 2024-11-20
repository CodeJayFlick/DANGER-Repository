Here is the translation of the Java code to Python:
```
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
```
Note that I had to create a separate `InvalidInputException` class in Python since it's not built-in like it is in Java. Also, the `CliCodedIndexUtils` functions are assumed to be implemented elsewhere in your codebase and imported as needed.

Also, please note that this translation assumes that you have already defined the equivalent of the following classes:

* `CliTypeTable`
* `CliStreamMetadata`

These should be replaced with their Python equivalents.