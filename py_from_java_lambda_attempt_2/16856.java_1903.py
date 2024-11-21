Here is the translation of the Java code to Python:
```
class SessionPoint:
    def __init__(self, host: str, rpc_port: int, username: str, password: str):
        self.host = host
        self.rpc_port = rpc_port
        self.username = username
        self.password = password

    @property
    def host(self) -> str:
        return self.host

    @property
    def rpc_port(self) -> int:
        return self.rpc_port

    @property
    def username(self) -> str:
        return self.username

    @property
    def password(self) -> str:
        return self.password

    def ip_and_port_to_string(self) -> str:
        return f"{self.host}-{self.rpc_port}"

SessionPoint.generate_ip_and_port_string = staticmethod(lambda host: int, rpc_port: f"{host}-{rpc_port}")
```
Note that I used the `@property` decorator to create read-only properties for each attribute. This is equivalent to Java's getter methods.

I also removed the `public` keyword since it's not necessary in Python. Additionally, I replaced the `return host + '-' + rpcPort;` statements with f-strings for better readability and conciseness.

The `generate_ip_and_port_string` method was translated to a staticmethod using the `staticmethod` decorator from the `functools` module. The lambda function is used to define the logic of this method, which is equivalent to Java's static method implementation.