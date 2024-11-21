Here is the equivalent Python code:

```Python
class EmptyContentLog:
    def __init__(self):
        pass

    def __init__(self, index: int, term: int):
        self.set_curr_log_index(index)
        self.set_curr_log_term(term)

    @staticmethod
    def serialize():
        buffer_size = 1024 * 8  # equivalent to DEFAULT_BUFFER_SIZE in Java
        byte_array_output_stream = bytearray(buffer_size)
        data_output_stream = bytes(byte_array_output_stream).makewriter()
        
        try:
            data_output_stream.write(int.to_bytes(EMPTY_CONTENT.ord(), 'B', False))
            data_output_stream.write(index_to_bytes(get_curr_log_index()))
            data_output_stream.write(index_to_bytes(get_curr_log_term()))
        except Exception as e:
            pass  # unreachable

    @staticmethod
    def deserialize(buffer: bytes):
        set_curr_log_index(int.from_bytes(buffer[:8], 'B', False))
        set_curr_log_term(int.from_bytes(buffer[8:], 'B', False))

    @staticmethod
    def to_string():
        return f"term: {get_curr_log_term()}, index: {get_curr_log_index()}"

def get_curr_log_index(self):
    # implement this method

def get_curr_log_term(self):
    # implement this method

def set_curr_log_index(self, value):
    # implement this method

def set_curr_log_term(self, value):
    # implement this method
```

Please note that the `EMPTY_CONTENT`, `get_curr_log_index`, `set_curr_log_index`, `get_curr_log_term` and `set_curr_log_term` methods are not implemented in Python as they were part of Java code.