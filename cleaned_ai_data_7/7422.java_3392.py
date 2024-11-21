import io

class SZByteProviderStream:
    def __init__(self, bp):
        self.bp = bp
        self.position = 0

    def seek(self, offset, origin):
        if origin == "set":
            self.set_pos(offset)
        elif origin == "cur":
            self.set_pos(self.position + offset)
        elif origin == "end":
            self.set_pos(self.bp.length() + offset)
        else:
            raise RuntimeError(f"Seek: unknown origin {origin}")

    def set_pos(self, new_pos):
        if new_pos < 0:
            raise SevenZipException("Invalid offset")
        self.position = new_pos

    def read(self, data):
        bytes_to_read = min(len(data), len(self.bp) - self.position)
        if bytes_to_read <= 0:
            return 0
        bytes = self.bp.read_bytes(self.position, bytes_to_read)
        data[:bytes_to_read] = bytes
        self.position += len(bytes)
        return len(bytes)

    def close(self):
        self.bp.close()

class SevenZipException(Exception):
    pass

class IOException(Exception):
    pass
