Here is the equivalent Python code:

```Python
import os
import fcntl


class FdInputStream:
    def __init__(self, fd):
        self.fd = fd
        self.closed = False

    def read(self, size=1):
        if self.closed:
            raise IOError("Stream closed")
        try:
            return os.read(self.fd, size)
        except OSError as e:
            if e.errno == 9:  # FD is invalid or not a file descriptor
                raise ValueError(f"Invalid file descriptor {self.fd}")
            else:
                raise

    def readinto(self, b):
        return self.read(len(b))

    def close(self):
        self.closed = True


# Example usage:

fd = os.open("/dev/tty", os.O_RDONLY)
stream = FdInputStream(fd)

data = stream.read(10)  # Read up to 10 bytes
print(data)

stream.close()
```

Note that Python's `os` module does not provide a direct equivalent of the POSIX file descriptor operations used in the original Java code. Instead, we use the `os.open()` function to open a file or device and get its file descriptor, and then use the `os.read()` function to read from it.

Also note that this Python implementation is not exactly equivalent to the original Java code. For example, the Java code uses jnr-ffi to invoke native functions, which is not possible in pure Python.