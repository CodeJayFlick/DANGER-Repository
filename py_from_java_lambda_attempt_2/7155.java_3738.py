Here is the equivalent Python code:

```Python
class FBPKConstants:
    FBPK = "FBPK"
    FBPT = "FBPT"
    PARTITION_TABLE = "partition table"
    LAST_PARTITION_ENTRY = "last_parti"

    PARTITION_TYPE_DIRECTORY = 0
    PARTITION_TYPE_FILE = 1

    NAME_MAX_LENGTH = 36
    VERSION_MAX_LENGTH = 68


def is_fbpk(program):
    try:
        memory = program.get_memory()
        bytes = bytearray(FBPKConstants.FBPK.encode())
        magic = memory.tobytes().decode('utf-8').strip()
        return FBPKConstants.FBPK == magic
    except Exception as e:
        pass  # ignore exceptions
    return False


# Example usage:
program = None  # replace with your program object
print(is_fbpk(program))
```

Note that Python does not have direct equivalents for Java's `public`, `final`, and `static` keywords. The equivalent of a public class in Python is simply defining the class without any special markers.