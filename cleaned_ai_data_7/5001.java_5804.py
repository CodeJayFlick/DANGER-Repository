class CliAbstractTable:
    def __init__(self, reader, metadata_stream, table_type):
        self.reader_offset = reader.tell()
        self.metadata_stream = metadata_stream
        self.table_type = table_type
        self.num_rows = metadata_stream.get_number_of_rows_for_table(table_type)
        self.rows = [None] * num_rows

    def get_table_type(self):
        return self.table_type

    def get_num_rows(self):
        return self.num_rows

    def get_row_size(self):
        row_data_type = self.get_row_data_type()
        if isinstance(row_data_type, int):
            return row_data_type
        else:
            return row_data_type.length()

    def get_table_size(self):
        return self.get_row_size() * self.get_num_rows()

    def get_row(self, index):
        if 0 <= index < self.num_rows:
            return self.rows[index]
        else:
            raise IndexError("Row index out of range")

    def markup(self, program, is_binary, task_monitor, message_log, nt_header):
        # Markup is not required
        pass

    def get_row_data_type(self):
        raise NotImplementedError("Subclass must implement this method")

    def to_data_type(self):
        row_dt = self.get_row_data_type()
        count = 1 if self.num_rows == 0 else self.num_rows
        array = Array(row_dt, count)
        try:
            array.set_category_path("/PE/CLI/Metadata/Tables")
        except DuplicateNameException as e:
            print(f"Warning: Duplication category path: {PATH}")
        return array

    def __str__(self):
        return str(self.table_type)

class CliTypeTable:
    pass  # This class is not implemented in the provided Java code, so it's left empty here.

def read_blob_index(reader):
    if metadata_stream.blob_index_data_type == DWordDataType.data_type:
        return reader.read_int()
    else:
        return reader.read_short() & 0xffff

def read_string_index(reader):
    if metadata_stream.string_index_data_type == DWordDataType.data_type:
        return reader.read_int()
    else:
        return reader.read_short() & 0xffff

def read_guid_index(reader):
    if metadata_stream.guid_index_data_type == DWordDataType.data_type:
        return reader.read_int()
    else:
        return reader.read_short() & 0xffff

def read_table_index(reader, table):
    if metadata_stream.table_index_data_type(table) == DWordDataType.data_type:
        return reader.read_int()
    else:
        return reader.read_short() & 0xffff
