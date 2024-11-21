Here is the translation of the Java code to Python:
```python
import io

class CliIndexImplementation:
    BITS_USED = 2
    TABLES = [CliTypeTable.File, CliTypeTable.AssemblyRef, CliTypeTable.ExportedType]

    @staticmethod
    def to_data_type(stream):
        return CliCodedIndexUtils.to_data_type(stream, CliIndexImplementation.BITS_USED, CliIndexImplementation.TABLES)

    @staticmethod
    def get_row_index(coded_index):
        return CliCodedIndexUtils.get_row_index(coded_index, CliIndexImplementation.BITS_USED)

    @staticmethod
    def get_table_name(coded_index):
        try:
            return CliCodedIndexUtils.get_table_name(coded_index, CliIndexImplementation.BITS_USED, CliIndexImplementation.TABLES)
        except Exception as e:
            raise InvalidInputException(str(e))

    @staticmethod
    def read_coded_index(reader, stream):
        try:
            return CliCodedIndexUtils.read_coded_index(reader, stream, CliIndexImplementation.BITS_USED, CliIndexImplementation.TABLES)
        except io.IOException as e:
            raise

class CliTypeTable:
    File = 0
    AssemblyRef = 1
    ExportedType = 2

class CliStreamMetadata:
    pass

class CliCodedIndexUtils:
    @staticmethod
    def to_data_type(stream, bits_used, tables):
        # implementation omitted for brevity
        pass

    @staticmethod
    def get_row_index(coded_index, bits_used):
        # implementation omitted for brevity
        pass

    @staticmethod
    def get_table_name(coded_index, bits_used, tables):
        # implementation omitted for brevity
        pass

    @staticmethod
    def read_coded_index(reader, stream, bits_used, tables):
        # implementation omitted for brevity
        pass
```
Note that I've kept the `CliCodedIndexUtils` class and its methods as-is, since they seem to be utility functions that don't have a direct equivalent in Python. You may need to implement these functions yourself or modify them to fit your specific use case.

Also, I didn't include any imports for modules like `io`, but you can add those if needed.