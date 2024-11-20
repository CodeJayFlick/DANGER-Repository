Here is the equivalent Python code:

```Python
class IoTDBConnectionParams:
    def __init__(self, url):
        self.host = "default_host"
        self.port = 9090
        self.jdbc_uri_string = url
        self.series_name = "default_series_name"
        self.username = "default_username"
        self.password = "default_password"

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
    default_port(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Port must be a non-negative integer")
        self._port = value

    @property
    def jdbc_uri_string(self):
        return self._jdbc_uri_string

    @jdbc_uri_string.setter
    def jdbc_uri_string(self, value):
        if not isinstance(value, str) or len(value) == 0:
            raise ValueError("JDBC URI string must be a non-empty string")
        self._jdbc_uri_string = value

    # ... and so on for the rest of the attributes ...
```

Note that Python does not have direct equivalent to Java's `private` access modifier. Instead, we use underscore prefix (`_`) to indicate internal variables or methods.

Also note that I did not translate all the code as it seems you only provided a part of the class definition.