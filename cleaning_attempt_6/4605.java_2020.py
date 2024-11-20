class LongNamesMember:
    LONGNAME_STR_TERM_CHARS = "\0\n"

    def __init__(self, reader, header):
        self._file_offset = reader.tell()
        tmp_offset = self._file_offset
        end_of_strings = tmp_offset + header.get_size()
        reader.seek(end_of_strings)
        
        while tmp_offset < end_of_strings:
            s = reader.read_terminated_string(tmp_offset, LONGNAME_STR_TERM_CHARS).decode('utf-8')
            tmp_offset += len(s) + 1
            self._n_strings += 1
            self.lengths.append(len(s) + 1)

    def get_file_offset(self):
        return self._file_offset

    def get_string_at_offset(self, provider, offset):
        reader = BinaryReader(provider, False)
        return reader.read_terminated_string(self._file_offset + offset, LONGNAME_STR_TERM_CHARS).decode('utf-8')

    def to_data_type(self):
        name = type(self).__name__
        unique_name = f"{name}_{self._n_strings}"
        struct = StructureDataType(unique_name, 0)
        
        for i in range(self._n_strings):
            struct.add(STRING, self.lengths[i], f"string[{i}]", None)

        return struct

    def find_name(self, provider, archive_member_header):
        nm = archive_member_header.get_name()
        if nm.startswith(CoffArchiveMemberHeader.SLASH):
            try:
                offset = int(nm[1:])
                nm = self.get_string_at_offset(provider, offset)
            except ValueError:
                pass
        elif nm.endswith(CoffArchiveMemberHeader.SLASH):
            nm = nm[:-1]
        
        return nm

class BinaryReader:
    def __init__(self, provider, is_big_endian):
        # assume the provider has a read method that returns bytes
        self.provider = provider
        self.is_big_endian = is_big_endian
    
    def tell(self):
        # implement this to get the current position in the file
        pass

    def seek(self, offset):
        # implement this to set the current position in the file
        pass

    def read_terminated_string(self, offset, term_chars):
        data = self.provider.read(offset)
        
        while True:
            if term_chars.encode('utf-8') in data:
                return data.decode('utf-8')
            else:
                data += self.provider.read(1)

class CoffArchiveMemberHeader:
    SLASH = "/"

class StructureDataType:
    def __init__(self, name, size):
        # implement this to create a structure data type
        pass

    def add(self, dtype, length, name, default_value):
        # implement this to add fields to the structure
        pass
