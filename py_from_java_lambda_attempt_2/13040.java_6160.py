Here is the equivalent Python code for the given Java code:

```Python
class BoundedInputStream:
    def __init__(self, wrapped_stream, size):
        self.wrapped_stream = wrapped_stream
        self.limit = size
        self.position = 0

    def read(self):
        if self.position >= self.limit:
            return -1
        self.position += 1
        return next(self.wrapped_stream)

    def readinto(self, b):
        if self.position >= self.limit:
            return 0
        bytes_left = min(self.limit - self.position, len(b))
        bytes_to_read = min(len(b), bytes_left)
        bytesRead = self.wrapped_stream.readinto(b[:bytes_to_read])
        if bytesRead > 0:
            self.position += bytesRead
        return bytesRead

    def close(self):
        try:
            self.wrapped_stream.close()
        except AttributeError:  # wrapped stream is not a file-like object, so it doesn't have a close method.
            pass

    def seek(self, n):
        bytes_left = self.limit - self.position
        to_seek = min(bytes_left, n)
        skipped = next(x for x in iter(lambda: self.wrapped_stream.read(1), b'') if not x)  # Read until we reach the desired position.
        self.position += skipped
        return skipped

# Example usage:
wrapped_file = open('example.txt', 'rb')
bounded_file = BoundedInputStream(wrapped_file, 1024)
print(bounded_file.read())  # Reads from the file up to a maximum of 1024 bytes.
```

Please note that Python's `readinto` method is not exactly equivalent to Java's `read(byte[] b, int off, int len)`. In Python, you would typically use a loop or list comprehension to read into a buffer.