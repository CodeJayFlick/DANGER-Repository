class PascalUtil:
    NO_OFFSET = 0
    ONE_BYTE_OFFSET = -1
    TWO_BYTE_OFFSET = -2
    
    ASCII_CHAR_WIDTH = 1
    UNICODE16_CHAR_WIDTH = 2
    PASCAL_LENGTH_SIZE_255 = 1
    PASCAL_LENGTH_SIZE = 2

    def find_pascal_sequence(buf, sequence, alignment):
        string_data_type = sequence.get_string_data_type()
        
        if isinstance(string_data_type, (PascalUnicodeDataType, UnicodeDataType)):
            return self.find_unicode_pascal(buf, sequence)
            
        elif isinstance(string_data_type, (PascalString255DataType, PascalStringDataType, StringDataType)):
            return self.find_ascii_pascal(buf, sequence, alignment)
            
        else:
            return None

    def find_unicode_pascal(self, buf, sequence):
        pascal_sequence = self.check_for_pascal_unicode_sequence(buf, sequence, self.TWO_BYTE_OFFSET)
        
        if pascal_sequence is not None:
            return pascal_sequence
        
        pascal_sequence = self.check_for_pascal_unicode_sequence(buf, sequence, self.NO_OFFSET)
        
        return pascal_sequence

    def find_ascii_pascal(self, buf, sequence, alignment):
        pascal_sequence = self.check_for_pascal_ascii_sequence(buf, sequence, self.TWO_BYTE_OFFSET)
        
        if pascal_sequence is not None:
            return pascal_sequence
        
        if alignment == 1:
            pascal_sequence = self.check_for_pascal255_ascii_sequence(buf, sequence, self.ONE_BYTE_OFFSET)
            
            if pascal_sequence is not None:
                return pascal_sequence
            
            pascal_sequence = self.check_for_pascal_ascii_sequence(buf, sequence, self.ONE_BYTE_OFFSET)
            
            if pascal_sequence is not None:
                return pascal_sequence
        
        pascal_sequence = self.check_for_pascal255_ascii_sequence(buf, sequence, self.NO_OFFSET)
        
        if pascal_sequence is not None:
            return pascal_sequence
        
        pascal_sequence = self.check_for_pascal_ascii_sequence(buf, sequence, self.NO_OFFSET)
        
        return pascal_sequence

    def check_for_pascal_unicode_sequence(self, buf, sequence, offset):
        pascal_length_offset = int(sequence.get_start()) + offset
        if pascal_length_offset < 0:
            return None
        
        length = self.get_short(buf, pascal_length_offset)
        
        sequence_length = (int(sequence.get_length()) - offset - PascalUtil.PASCAL_LENGTH_SIZE) // PascalUtil.UNICODE16_CHAR_WIDTH
        
        if sequence.is_null_terminated():
            sequence_length -= 1
            
            if length == sequence_length:
                return Sequence(pascal_length_offset, int(sequence.get_end()) - PascalUtil.UNICODE16_CHAR_WIDTH, PascalUnicodeDataType.data_type, False)
        
        elif length == sequence_length:
            return Sequence(pascal_length_offset, int(sequence.get_end()), PascalUnicodeDataType.data_type, False)
        
        return None

    def check_for_pascal_ascii_sequence(self, buf, sequence, offset):
        pascal_length_offset = int(sequence.get_start()) + offset
        if pascal_length_offset < 0:
            return None
        
        length = self.get_short(buf, pascal_length_offset)
        
        sequence_length = int(sequence.get_length()) - offset - PascalUtil.PASCAL_LENGTH_SIZE
        
        if sequence.is_null_terminated():
            sequence_length -= 1
            
            if length == sequence_length:
                return Sequence(pascal_length_offset, int(sequence.get_end()) - PascalUtil.ASCII_CHAR_WIDTH, PascalStringDataType.data_type, False)
        
        elif length == sequence_length:
            return Sequence(pascal_length_offset, int(sequence.get_end()), PascalStringDataType.data_type, False)
        
        return None

    def check_for_pascal255_ascii_sequence(self, buf, sequence, offset):
        pascal_length_offset = int(sequence.get_start()) + offset
        if pascal_length_offset < 0:
            return None
        
        length = self.get_byte(buf, pascal_length_offset) & 0xff
        
        sequence_length = int(sequence.get_length()) - offset - PascalUtil.PASCAL_LENGTH_SIZE_255
        
        if sequence.is_null_terminated():
            sequence_length -= 1
            
            if length == sequence_length:
                return Sequence(pascal_length_offset, int(sequence.get_end()) - PascalUtil.ASCII_CHAR_WIDTH, PascalString255DataType.data_type, False)
        
        elif length == sequence_length:
            return Sequence(pascal_length_offset, int(sequence.get_end()), PascalString255DataType.data_type, False)
        
        return None

    def get_short(self, buf, offset):
        try:
            return buf.get_short(offset)
        except MemoryAccessException as e:
            return PascalUtil.ONE_BYTE_OFFSET
    
    def get_byte(self, buf, offset):
        try:
            return buf.get_byte(offset) & 0xff
        except MemoryAccessException as e:
            return PascalUtil.ONE_BYTE_OFFSET

class Sequence:
    pass

class PascalUnicodeDataType:
    data_type = None

class UnicodeDataType:
    pass

class PascalString255DataType:
    data_type = None

class StringDataType:
    pass
