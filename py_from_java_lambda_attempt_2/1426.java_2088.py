Here is the translation of the Java code to Python:
```
import os

class LinuxPtyEndpoint:
    def __init__(self, fd):
        self.output_stream = open(fd, 'wb')
        self.input_stream = open(fd, 'rb')

    def get_output_stream(self):
        return self.output_stream

    def get_input_stream(self):
        return self.input_stream
```
Note that I've used the `os` module to interact with file descriptors in Python. The `open()` function is used to create file objects for reading and writing, similar to how Java's `FdOutputStream` and `FdInputStream` classes work.

Also, since Python doesn't have a direct equivalent of Java's `PtyEndpoint` interface, I've simply created a class with the same name (`LinuxPtyEndpoint`) that implements the same methods.