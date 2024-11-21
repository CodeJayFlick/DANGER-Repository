class DebugHostMemoryImpl1:
    def __init__(self, jna_data):
        self.cleanable = DbgModel.release_when_phantom(self, jna_data)
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def read_bytes(self, context, location, buffer, bufferSize):
        if bufferSize > buffer.remaining():
            raise BufferOverflowException()
        
        p_context = context.get_pointer()
        pul_buffer_size = int(bufferSize)
        bytes_read = self.jna_data.read_bytes(p_context, location, buffer, pul_buffer_size)
        buffer.position(int(bytes_read + buffer.position()))
        return bytes_read

    def write_bytes(self, context, location, buffer, bufferSize):
        if bufferSize > buffer.remaining():
            raise BufferOverflowException()
        
        p_context = context.get_pointer()
        pul_buffer_size = int(bufferSize)
        bytes_written = self.jna_data.write_bytes(p_context, location, buffer, pul_buffer_size)
        buffer.position(int(bytes_written + buffer.position()))
        return bytes_written

    def read_pointers(self, context, location, count):
        p_context = context.get_pointer()
        p_count = int(count)
        p_pointers = self.jna_data.read_pointers(p_context, location, p_count)
        return p_pointers

    def write_pointers(self, context, location, count):
        p_context = context.get_pointer()
        p_count = int(count)
        p_pointers = self.jna_data.write_pointers(p_context, location, p_count)
        return p_pointers

    def get_display_string_for_location(self, context, location, verbose):
        p_context = context.get_pointer()
        b_verbose = bool(verbose)
        display_string = self.jna_data.get_display_string_for_location(p_context, location, b_verbose).decode('utf-8')
        return display_string
