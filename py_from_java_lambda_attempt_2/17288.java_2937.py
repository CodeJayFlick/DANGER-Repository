Here is the translation of the given Java code into Python:

```Python
class DeletePlan:
    def __init__(self):
        self.delete_start_time = None
        self.delete_end_time = None
        self.paths = []

    def __init__(self, start_time, end_time, path=None):
        if path is not None:
            self.paths.append(path)
        else:
            self.delete_start_time = start_time
            self.delete_end_time = end_time

    @property
    def delete_start_time(self):
        return self._delete_start_time

    @delete_start_time.setter
    def delete_start_time(self, value):
        self._delete_start_time = value

    @property
    def delete_end_time(self):
        return self._delete_end_time

    @delete_end_time.setter
    def delete_end_time(self, value):
        self._delete_end_time = value

    def add_path(self, path):
        if isinstance(path, list):
            self.paths.extend(path)
        else:
            self(paths).append(path)

    def get_paths(self):
        return self.paths

    @property
    def partition_filter(self):
        return self._partition_filter

    @partition_filter.setter
    def partition_filter(self, value):
        self._partition_filter = value

    def __hash__(self):
        return hash((self.delete_start_time, self.delete_end_time, tuple(self(paths))))

    def __eq__(self, other):
        if not isinstance(other, DeletePlan):
            return False
        return (self.delete_start_time == other.delete_start_time and 
                self.delete_end_time == other.delete_end_time and 
                set(self.paths) == set(other.get_paths()))

    def serialize_to_stream(self, stream):
        type = 0  # DELETE
        stream.write_byte(type)
        stream.write_long(self.delete_start_time)
        stream.write_long(self.delete_end_time)
        stream.write_int(len(self(paths)))
        for path in self(paths):
            stream.write_string(path.get_full_path())
        if hasattr(stream, 'write_long'):
            stream.write_long(0)  # index

    def serialize_to_buffer(self, buffer):
        type = 0  # DELETE
        buffer.put(type)
        buffer.put_long(self.delete_start_time)
        buffer.put_long(self.delete_end_time)
        buffer.putInt(len(self(paths)))
        for path in self(paths):
            buffer.put_string(path.get_full_path())
        if hasattr(buffer, 'put_long'):
            buffer.put_long(0)  # index

    def deserialize_from_buffer(self, buffer):
        self.delete_start_time = buffer.get_long()
        self.delete_end_time = buffer.get_long()
        size = buffer.get_int()
        self.paths = [PartialPath(read_string(buffer)) for _ in range(size)]
```

Please note that the above Python code is a direct translation of your Java code. However, it may not work as expected if you are using some specific libraries or frameworks which were used in your original Java code.