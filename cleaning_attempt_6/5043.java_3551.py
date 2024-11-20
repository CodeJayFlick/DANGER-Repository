class CliCodedIndexUtils:
    @staticmethod
    def to_data_type(stream, bits_used, tables):
        max_for_word = (1 << ((WordDataType().get_length() * 8) - bits_used)) - 1
        for table in tables:
            if table is not None and stream.get_number_rows_for_table(table) > max_for_word:
                return DWordDataType()
        return WordDataType()

    @staticmethod
    def get_table_name(coded_index, bits_used, tables):
        mask = (2 << (bits_used - 1)) - 1
        table_bits = coded_index & mask
        if table_bits >= len(tables):
            raise InvalidInputException("The coded index is not valid for this index type. There is no TableName for the bit pattern.")
        return tables[table_bits]

    @staticmethod
    def get_row_index(coded_index, bits_used):
        return coded_index >> bits_used

    @staticmethod
    def read_coded_index(reader, stream, bits_used, tables):
        if CliCodedIndexUtils.to_data_type(stream, bits_used, tables).get_length() == WordDataType().get_length():
            return reader.read_next_short()
        return reader.read_next_int()

class InvalidInputException(Exception):
    pass

class DWordDataType:
    @staticmethod
    def get_length():
        # You need to implement this method in your actual code.
        pass

class WordDataType:
    @staticmethod
    def get_length():
        # You need to implement this method in your actual code.
        pass
