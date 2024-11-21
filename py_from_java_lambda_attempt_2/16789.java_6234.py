Here is the equivalent Python code:

```Python
class IoTDBOptions:
    def __init__(self, host=None, port=None, user=None, password=None):
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        self._host = value

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = value

    @property
    def user(self):
        return self._user

    @user.setter
    def user(self, value):
        self._user = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value


# Example usage:
options = IoTDBOptions("localhost", 6667, "iotdb", "root")
print(options.host)  # prints: localhost
```

Note that Python does not have a direct equivalent to Java's `Serializable` interface. If you need serialization support for this class, you would typically use the built-in `pickle` module or another serialization library like `json`.