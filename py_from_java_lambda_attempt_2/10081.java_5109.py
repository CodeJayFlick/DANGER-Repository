Here is the equivalent Python code:

```Python
class RMIServerPortFactory:
    REGISTERY_PORT = 0
    RMI_SSL_PORT = 1
    STREAM_PORT = 2

    def __init__(self, base_port):
        self.base_port = base_port

    def get_rmi_registry_port(self):
        return self.base_port + self.REGISTERY_PORT

    def get_rmisslport(self):
        return self.base_port + self.RMI_SSL_PORT

    def get_stream_port(self):
        return self.base_port + self.STREAM_PORT
```

Note that Python does not have a direct equivalent to Java's `package` statement, so the package declaration is omitted. Also, Python uses indentation instead of curly braces for block-level structure, and it has no concept of public or private access modifiers like Java does.