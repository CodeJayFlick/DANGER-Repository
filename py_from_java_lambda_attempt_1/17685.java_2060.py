Here is the translation of the Java code into Python:

```Python
import io
from typing import ThreadLocal


class IOUtils:
    def __init__(self):
        pass

    @staticmethod
    def write_string(output_stream: io.IOBase, str_value: str, encoding: str) -> None:
        if str_value is not None:
            str_buffer = str_value.encode(encoding)
            output_stream.write(str_buffer)
        else:
            output_stream.write(b'')

    @staticmethod
    def write_int(output_stream: io.IOBase, int_value: int) -> None:
        output_stream.write(int_to_bytes(int_value))

    @staticmethod
    def read_string(input_stream: io.IOBase, encoding: str) -> str:
        length = input_stream.read_int()
        if length > 0:
            str_buffer = bytearray(length)
            input_stream.readinto(str_buffer)
            return str(str_buffer.decode(encoding))
        else:
            return ''

    @staticmethod
    def read_path_privilege(input_stream: io.IOBase, encoding: str) -> 'PathPrivilege':
        path = IOUtils.read_string(input_stream, encoding)
        privilege_num = input_stream.read_int()
        path_privilege = PathPrivilege(path)
        for _ in range(privilege_num):
            path_privilege.privileges.append(input_stream.read_int())
        return path_privilege

    @staticmethod
    def write_path_privilege(output_stream: io.IOBase, path_privilege: 'PathPrivilege', encoding: str) -> None:
        IOUtils.write_string(output_stream, path_privilege.path, encoding)
        output_stream.write(int_to_bytes(len(path_privilege.privileges)))
        for privilege in path_privilege.privileges:
            output_stream.write(int_to_bytes(privilege))

    @staticmethod
    def replace_file(new_file: 'File', old_file: 'File') -> None:
        if not new_file.replace(old_file):
            if not old_file.delete():
                raise IOException(f"Cannot delete old user file {old_file.path}")
            if not new_file.replace(old_file):
                raise IOException(f"Cannot replace old user file with new one {new_file.path}")

    @staticmethod
    def clone(original: 'ByteBuffer') -> 'ByteBuffer':
        return ByteBuffer.wrap(bytearray(original))


class PathPrivilege:
    def __init__(self, path: str):
        self.path = path
        self.privileges = []

def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')
```

Note that Python does not have a direct equivalent to Java's `ThreadLocal` class. Instead, you can use the built-in threading module and create your own thread-local storage using dictionaries or other data structures.

Also note that this code is just an approximation of how the original Java code would look in Python. The actual translation may vary depending on specific requirements and constraints.