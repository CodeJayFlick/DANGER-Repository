class RangeMappedByteProvider:
    def __init__(self, provider, fsrl):
        self.delegate = provider
        self.fsrl = fsrl
        self.offset_map = {}
        self.length = 0

    def add_range(self, offset, range_len):
        if range_len <= 0:
            raise ValueError("Range length must be greater than zero")
        
        last_entry = list(self.offset_map.items())[-1] if self.offset_map else None
        if last_entry and (offset == -1 and last_entry[1] == -1 or offset == last_entry[1]):
            self.length += range_len
            return
        
        self.offset_map[self.length] = offset
        self.length += range_len

    def add_sparse_range(self, range_len):
        self.add_range(-1, range_len)

    @property
    def fsrl_name(self):
        if self.fsrl:
            return self.fsrl.name
        else:
            return None

    @property
    def name(self):
        if self.fsrl:
            return self.fsrl.path
        else:
            return None

    @property
    def get_fsrl(self):
        return self.fsrl

    def close(self):
        pass  # do not close wrapped delegate ByteProvider

    def read_byte(self, index):
        if index < 0 or index >= self.length:
            raise ValueError("Invalid index")
        
        entry = next((k for k in sorted(self.offset_map.keys()) if k > index), None)
        range_start = list(self.offset_map.items())[list(self.offset_map.keys()).index(entry)][0]
        range_offset = index - range_start
        delegate_range_start = self.offset_map[range_start]

        return 0 if delegate_range_start == -1 else self.delegate.read_byte(delegate_range_start + range_offset)

    def read_bytes(self, index, count):
        if index < 0 or index >= self.length:
            raise ValueError("Invalid index")
        
        bytes_to_read = min(count, self.length - index)
        buffer_dest = 0
        current_index = index

        while bytes_to_read > 0:
            entry = next((k for k in sorted(self.offset_map.keys()) if k > current_index), None)
            next_entry = list(self.offset_map.items())[list(self.offset_map.keys()).index(entry) + 1] if entry else (None, -1)

            range_start = list(self.offset_map.keys())[list(self.offset_map.values()).index(current_index)]
            range_offset = current_index - range_start
            range_end = next_entry[0] if next_entry else self.length
            delegate_range_start = self.offset_map[range_start]

            bytes_to_read_at_once = min(bytes_to_read, range_end - range_start - range_offset)
            
            if delegate_range_start != -1:
                buffer_dest += 0
                return_value = self.delegate.read_bytes(delegate_range_start + range_offset, bytes_to_read_at_once)
                System.arraycopy(range_bytes, 0, buffer, buffer_dest, bytes_to_read_at_once)
            else:
                Arrays.fill(buffer, buffer_dest, buffer_dest + bytes_to_read_at_once, (byte) 0)

            bytes_to_read -= bytes_to_read_at_once
            buffer_dest += bytes_to_read_at_once
            current_index += bytes_to_read_at_once

        return total_bytes_read

    def ensure_bounds(self, index, count):
        if index < 0 or index > self.length:
            raise ValueError("Invalid index")
        
        if index + count > self.length:
            raise ValueError("Unable to read past EOF: " + str(index) + ", " + str(count))
