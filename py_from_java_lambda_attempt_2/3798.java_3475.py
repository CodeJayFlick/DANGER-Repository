Here is the translation of the Java code to Python:
```
import subprocess
import socket

class EclipseConnection:
    def __init__(self):
        self.process = None
        self.socket = None

    def __init__(process=None, socket=None):
        self.process = process
        self.socket = socket

    @property
    def process(self):
        return self._process

    @process.setter
    def process(self, value):
        self._process = value

    @property
    def socket(self):
        return self._socket

    @socket.setter
    def socket(self, value):
        self._socket = value

    def get_process(self):
        return self.process

    def get_socket(self):
        return self.socket
```
Note that I've used Python's `@property` decorator to create getter and setter methods for the `process` and `socket` attributes. This is equivalent to Java's public getters and setters.

Also, in Python, we don't need a separate constructor method like Java does with its `__init__()` method. Instead, we can define multiple `__init__()` methods that take different arguments, or use keyword arguments (`**kwargs`) to pass additional parameters.

Finally, I've removed the Javadoc-style comments from the code, as they are not necessary in Python.