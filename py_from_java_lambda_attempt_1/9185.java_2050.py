Here is the translation of the Java code to Python:

```Python
class ManagedBufferFileAdapter:
    def __init__(self, managed_buffer_file_handle):
        self.managed_buffer_file_handle = managed_buffer_file_handle

    def get_save_file(self) -> 'ManagedBufferFile':
        save_file = self.managed_buffer_file_handle.get_save_file()
        if save_file is not None:
            return ManagedBufferFileAdapter(save_file)
        else:
            return None

    def save_completed(self, commit: bool):
        self.managed_buffer_file_handle.save_completed(commit)

    def can_save(self) -> bool:
        return self.managed_buffer_file_handle.can_save()

    def set_version_comment(self, comment: str):
        self.managed_buffer_file_handle.set_version_comment(comment)

    def get_next_change_data_file(self, get_first: bool) -> 'BufferFile':
        next_change_data_file = self.managed_buffer_file_handle.get_next_change_data_file(get_first)
        if next_change_data_file is not None:
            return BufferFileAdapter(next_change_data_file)
        else:
            return None

    def get_save_change_data_file(self) -> 'BufferFile':
        save_change_data_file = self.managed_buffer_file_handle.get_save_change_data_file()
        if save_change_data_file is not None:
            return BufferFileAdapter(save_change_data_file)
        else:
            return None

    def get_checkin_id(self):
        return self.managed_buffer_file_handle.get_checkin_id()

    def get_forward_mod_map_data(self, old_version: int) -> bytes:
        return self.managed_buffer_file_handle.get_forward_mod_map_data(old_version)

    def get_input_block_stream(self, change_map_data: bytes) -> 'InputBlockStream':
        if isinstance(self.managed_buffer_file_handle, Remote):
            input_block_stream = InputBlockStreamHandle(self.managed_buffer_file_handle.get_input_block_stream_handle(change_map_data)).open_block_stream()
        else:
            input_block_stream = self.managed_buffer_file_handle.get_input_block_stream(change_map_data)
        return input_block_stream


class BufferFileAdapter:
    def __init__(self, buffer_file):
        self.buffer_file = buffer_file

    # ... other methods ...


class ManagedBufferFileHandle:
    pass  # This class is not implemented in the provided Java code.


class InputBlockStreamHandle:
    def open_block_stream(self) -> 'InputBlockStream':
        return None  # This method should be implemented.
```

Please note that this translation assumes that `Remote`, `IOException`, and other classes are part of Python's standard library. If they're not, you'll need to import them from a different module or define your own versions.

Also, the code doesn't include implementations for some methods like `BufferFileAdapter`'s constructor and others in `ManagedBufferFileHandle`.