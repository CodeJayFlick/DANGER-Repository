import datetime

class YAFFS2Utils:
    def parse_name(self, buffer, offset, length):
        result = ""
        end = offset + length
        
        for i in range(offset, end):
            b = buffer[i]
            if b == 0:  # Trailing null
                break
            result += chr(b & 0xFF)  # Allow for sign-extension
            
        return result

    def parse_integer(self, buffer, offset, length):
        result = 0
        end = offset + length
        start = offset
        j = 0
        
        for i in range(start, end):
            result += (buffer[i] & 0xFF) << (8 * j)
            j += 1
            
        return result

    def parse_file_size(self, buffer, offset, length):
        result = 0
        end = offset + length
        start = offset
        j = 0
        
        for i in range(start, end):
            if buffer[i] == -1:  # check for special case (dir header)
                return 0
            
            result += (buffer[i] & 0xFF) << (8 * j)
            j += 1
        
        return result

    def parse_date_time(self, buffer, offset, length):
        result = 0
        end = offset + length
        start = offset
        j = 0
        
        for i in range(start, end):
            result += (buffer[i] & 0xFF) << (8 * j)
            j += 1
            
        return datetime.datetime.fromtimestamp(result / 1000).strftime('%Y-%m-%d %H:%M:%S')

    @classmethod
    def is_yaffs2_image(cls, program):
        bytes = bytearray(YAFFS2Constants.MAGIC_SIZE)
        
        try:
            address = program.get_min_address()
            program.get_memory().get_bytes(address, bytes)
        except Exception as e:
            pass
        
        # check for initial byte equal to 0x03 (directory) and 
        # the first byte of the file name is null
        return ((bytes[0] == 3) and (bytes[10] == 0))
