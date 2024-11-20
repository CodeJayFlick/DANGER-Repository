import zlib
import io

class DataBuffer:
    serialVersionUID = 3
    
    COMPRESSED_SERIALIZATION_OUTPUT_PROPERTY = "db.buffers.DataBuffer.compressedOutput"
    
    @classmethod
    def enable_compressed_serialization_output(cls, enable):
        import os
        if not hasattr(cls, 'compressedSerializationOutput'):
            cls.compressedSerializationOutput = False
        
        if enable:
            os.environ[cls.COMPRESSED_SERIALIZATION_OUTPUT_PROPERTY] = str(enable)
            cls.compressedSerializationOutput = True
        else:
            del os.environ[cls.COMPRESSED_SERIALIZATION_OUTPUT_PROPERTY]
            cls.compressedSerializationOutput = False
    
    @classmethod
    def using_compressed_serialization_output(cls):
        return cls.compressedSerializationOutput

    FORMAT_VERSION = 0xEA

    def __init__(self):
        pass

    def __init__(self, bufsize):
        self.data = bytearray(bufsize)
    
    def __init__(self, data):
        self.data = bytearray(data)

    @property
    def id(self):
        return self._id
    
    @id.setter
    def id(self, value):
        self._id = value

    @property
    def dirty(self):
        return self._dirty
    
    @dirty.setter
    def dirty(self, state):
        self._dirty = state

    @property
    def empty(self):
        return self._empty
    
    @empty.setter
    def empty(self, state):
        self._empty = state

    def length(self):
        return len(self.data)

    def get(self, offset, bytes, data_offset=0, length=None):
        if length is None:
            length = len(bytes) - data_offset
        
        bytes[data_offset:data_offset+length] = self.data[offset:offset+length]

    def put(self, offset, bytes, data_offset=0, length=None):
        if length is None:
            length = len(bytes) - data_offset

        self.dirty = True
        self.data[offset:offset+length] = bytes[data_offset:data_offset+length]
        
        return offset + length
    
    def clear(self):
        for i in range(len(self.data)):
            self.data[i] = 0

    def move(self, src, dest, length):
        if src < 0 or dest < 0:
            raise ValueError("Invalid source or destination")
        
        if src >= len(self.data) or dest >= len(self.data):
            raise ValueError("Source or destination out of bounds")

        self.dirty = True
        for i in range(length):
            self.data[dest+i] = self.data[src+i]

    def copy(self, offset, buf, buf_offset=0, length=None):
        if length is None:
            length = len(buf) - buf_offset
        
        self.dirty = True
        self.data[offset:offset+length] = buf[buf_offset:buf_offset+length]
        
        return offset + length

    def writeExternal(self, out):
        compressed = DataBuffer.using_compressed_serialization_output()
        if not (self.empty or self.data is None) and compressed:
            data_len = len(self.data)
            compressed_data = bytearray(data_len)
            compressed_len = zlib.compress(self.data, level=9)

            if compressed_len < 0:
                compressed = False

            out.write_int(DataBuffer.FORMAT_VERSION)
            out.write_bool(compressed)

            out.write_int(self.id)
            out.write_bool(self.dirty)
            out.write_bool(self.empty)

            if self.data is None:
                out.write_int(-1)
            else:
                out.write_int(data_len)

                if compressed:
                    out.write_int(len(compressed_data))
                    out.write(compressed_data[:compressed_len])
                else:
                    out.write(self.data)

    def readExternal(self, in):
        format_version = in.read_int()
        if format_version != DataBuffer.FORMAT_VERSION:
            raise ValueError("Unsupported serialization")

        compressed = in.read_bool()

        self.id = in.read_int()
        self.dirty = in.read_bool()
        self.empty = in.read_bool()
        
        data_len = in.read_int()
        
        self.data = bytearray(data_len)

        if compressed:
            compressed_len = in.read_int()
            compressed_data = bytearray(compressed_len)
            in.read(compressed_data[:compressed_len])
            
            try:
                inflated_len = zlib.inflate(compressed_data, level=9).nbytes
                inflated_data = bytearray(inflated_len)
                
                in.read(inflated_data)
                self.data[:] = inflated_data[:]
            except Exception as e:
                raise ValueError("DataBuffer deserialization failed", e)
        else:
            in.read(self.data)

    def unsignedCompareTo(self, other_data, offset=0, length=None):
        if length is None:
            length = len(other_data) - offset
        
        n = min(len(self.data), length)
        
        while n > 0:
            b1 = self.data[offset] & 0xff
            b2 = other_data[offset + length - n] & 0xff
            
            if b1 != b2:
                return b1 - b2

            offset += 1
            n -= 1
        
        return len(self.data) - length
    
    @staticmethod
    def inflateData(compressed_data, data):
        inflater = zlib.Inflater()
        
        try:
            off = 0
            
            while not inflater.finished() and off < len(data):
                off += inflater.inflate(data, off, len(data) - off)
                
                if inflater.needsDictionary():
                    raise ValueError("DataBuffer dictionary error")
            
            if not inflater.finished():
                raise ValueError("DataBuffer inflate size error")
        except zlib.DataFormatException as e:
            raise ValueError("DataBuffer inflation failed", e)

if __name__ == "__main__":
    pass
