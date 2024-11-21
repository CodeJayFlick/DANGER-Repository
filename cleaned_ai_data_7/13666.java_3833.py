class GRandomAccessFile:
    EMPTY = bytearray(0)
    BUFFER_SIZE = 2**20

    def __init__(self, file, mode):
        self.file = file
        if mode not in ["r", "rw", "rws", "rwd"]:
            raise ValueError("Invalid mode")
        try:
            with open(file, mode) as f:
                pass
        except FileNotFoundError:
            raise FileNotFoundError(f"File {file} does not exist")

    def close(self):
        self.file = None

    def length(self):
        return self.file.seek(0, 2)

    def seek(self, pos):
        if pos < 0:
            raise ValueError("pos cannot be less than zero")
        if pos < self.buffer_file_start_index or pos >= self.buffer_file_start_index + len(self.buffer):
            # check if the last buffer contained it, and swap in if necessary
            self.swap_in_last()
            if pos < self.buffer_file_start_index or pos >= self.buffer_file_start_index + len(self.buffer):
                # not in either, gotta get a new one
                self.buffer = bytearray(0)
                self.buffer_offset = 0
                self.buffer_file_start_index = pos

        self.buffer_offset = pos - self.buffer_file_start_index

    def read_byte(self):
        if self.buffer_offset >= len(self.buffer):
            self.read(BUFFER_SIZE)

        return self.buffer[self.buffer_offset]

    def read(self, b, offset=0, length=None):
        if not isinstance(b, bytearray) or not 0 <= offset < len(b):
            raise ValueError("Invalid buffer")

        bytes_read = min(length or len(b), BUFFER_SIZE - (self.buffer_file_start_index + self.buffer_offset))
        with open(self.file.name, 'rb') as f:
            f.seek(self.buffer_file_start_index)
            f.readinto(self.buffer[:bytes_read])
        for i in range(bytes_read):
            b[offset+i] = self.buffer[i]

        if bytes_read < length or len(b) - offset <= BUFFER_SIZE - (self.buffer_file_start_index + self.buffer_offset):
            return bytes_read

    def write(self, b, offset=0, length=None):
        with open(self.file.name, 'wb') as f:
            f.seek(self.buffer_file_start_index)
            if not isinstance(b, bytearray) or not 0 <= offset < len(b):
                raise ValueError("Invalid buffer")
            bytes_written = min(length or len(b), BUFFER_SIZE - (self.buffer_file_start_index + self.buffer_offset))
            for i in range(bytes_written):
                f.write(bytearray([b[offset+i]]))

    def ensure(self, bytes_needed):
        if self.buffer_offset + bytes_needed > len(self.buffer):
            # check if the last buffer contained it, and swap in if necessary
            old_file_start_index = self.buffer_file_start_index
            old_buffer_offset = self.buffer_offset
            old_seek_pos = old_file_start_index + old_buffer_offset

            if old_seek_pos < self.buffer_file_start_index or \
               old_seek_pos >= self.buffer_file_start_index + BUFFER_SIZE:
                # must ensure that current read pos is in old buffer, and enough bytes
                new_buffer_offset = (old_seek_pos - self.buffer_file_start_index)
                if old_seek_pos < self.buffer_file_start_index or \
                   old_seek_pos >= self.buffer_file_start_index + BUFFER_SIZE or \
                   (new_buffer_offset + bytes_needed > len(self.buffer)):
                    # swap em and return
                    buffer_swap = bytearray(self.buffer)
                    offset_swap = self.buffer_offset
                    file_start_index_swap = self.buffer_file_start_index

                    self.buffer = lastbuffer
                    self.buffer_offset = lastbuffer_offset
                    self.buffer_file_start_index = lastbuffer_file_start_index

                    lastbuffer = buffer_swap
                    lastbuffer_offset = offset_swap
                    lastbuffer_file_start_index = file_start_index_swap

    def swap_in_last(self):
        if len(self.buffer) == 0:
            return
        # swap em and return
        buffer_swap = bytearray(self.buffer)
        offset_swap = self.buffer_offset
        file_start_index_swap = self.buffer_file_start_index

        self.buffer = lastbuffer
        self.buffer_offset = lastbuffer_offset
        self.buffer_file_start_index = lastbuffer_file_start_index

        lastbuffer = buffer_swap
        lastbuffer_offset = offset_swap
        lastbuffer_file_start_index = file_start_index_swap


# Usage example:
file = open("test.txt", "r")
graf = GRandomAccessFile(file, "rw")

print(graf.length())
graf.seek(0)
print(graf.read_byte())

try:
    graf.write(bytearray([1]))
except Exception as e:
    print(f"Error: {e}")

# Don't forget to close the file
file.close()
