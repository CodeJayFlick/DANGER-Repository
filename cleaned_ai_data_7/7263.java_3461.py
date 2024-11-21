class NSObjectParser:
    @staticmethod
    def parse_object(reader, object_offset, trailer):
        reader.set_pointer_index(object_offset)
        
        object_descriptor = reader.read_next_byte()
        object_type = (object_descriptor & 0xf0) >> 4
        object_info = object_descriptor & 0x0f
        
        if object_type == 0:
            if object_info in [0, 8, 9]:
                return NSNumber(false)
            elif object_info == 12:  # URL w/ base URL TODO
                pass
            elif object_info == 13:  # URL w/o base URL TODO
                pass
            else:
                raise IOException("WARNING: The binary PLIST contains unknown SIMPLE object type: " + str(object_info))
        elif object_type == 1:
            length = (2 ** object_info)
            if length in [1, 2, 4]:
                value = reader.read_next_byte() if length == 1 else \
                        reader.read_short() if length == 2 else \
                        reader.read_int()
                return NSNumber(value)
            else:
                raise IOException("WARNING: Invalid integer length specified in the binary PList.")
        elif object_type == 2:
            length = (2 ** object_info)
            if length == 4:
                int_value = reader.read_int()
                float_value = Float.intBitsToFloat(int_value)
                return NSNumber(float_value)
            elif length == 8:
                long_value = reader.read_long()
                double_value = Double.longBitsToDouble(long_value)
                return NSNumber(double_value)
            else:
                raise IOException("WARNING: Invalid real number length specified in the binary PList.")
        elif object_type == 3:
            if object_info != 3:
                raise IOException("WARNING: Binary PLIST contains unknown date type:" + str(object_info))
            long_value = reader.read_long()
            double_value = Double.longBitsToDouble(long_value)
            return NSDate(double_value)
        elif object_type in [4, 5, 6]:
            length = parse_length(reader, object_info)
            if object_type == 4:
                return NSData(reader.read_next_byte_array(length))
            else:
                return NSString(reader.read_next_ascii_string(length), 'ascii' if object_type == 5 else 'utf16be')
        elif object_type in [8, a]:
            length = parse_length(reader, object_info)
            array = []
            for _ in range(length):
                value = reader.read_next_byte() if trailer.get_object_ref_size() == 1 else \
                        reader.read_short() if trailer.get_object_ref_size() == 2 else \
                        reader.read_int()
                array.append(value)
            return NSArray(array, trailer.get_object_ref_size())
        elif object_type in [c, d]:
            length = parse_length(reader, object_info)
            set = NSSet(True, trailer.get_object_ref_size())
            for _ in range(length):
                value = reader.read_next_byte() if trailer.get_object_ref_size() == 1 else \
                        reader.read_short() if trailer.get_object_ref_size() == 2 else \
                        reader.read_int()
                set.add(value)
            return set
        elif object_type == d:
            length = parse_length(reader, object_info)
            dictionary = NSDictionary(trailer.get_object_ref_size())
            for _ in range(length):
                key = reader.read_next_byte() if trailer.get_object_ref_size() == 1 else \
                        reader.read_short() if trailer.get_object_ref_size() == 2 else \
                        reader.read_int()
                value = reader.read_next_byte() if trailer.get_object_ref_size() == 1 else \
                        reader.read_short() if trailer.get_object_ref_size() == 2 else \
                        reader.read_int()
                dictionary.put(key, value)
            return dictionary
        else:
            raise IOException("WARNING: The binary PLIST contains unknown object type: " + str(object_type))

    @staticmethod
    def parse_length(reader, object_info):
        length = object_info
        if object_info == 15:  # longer than 0xf bytes...
            offset = reader.read_next_byte()
            if offset == 16:
                length = reader.read_next_byte() & 0xff
            elif offset == 17:
                length = reader.read_short() & 0xffff
            else:
                raise RuntimeError()
        return length


class BinaryReader:
    def __init__(self):
        pass

    def set_pointer_index(self, index):
        pass

    def read_next_byte(self):
        pass

    def read_short(self):
        pass

    def read_int(self):
        pass

    def read_long(self):
        pass

    def read_next_ascii_string(self, length):
        pass

    def read_next_unicode_string(self, length):
        pass

    def read_next_byte_array(self, length):
        pass
