Here is the translation of the Java code to Python:
```
class DebugRunningProcessImpl:
    def __init__(self, client: 'DebugClientInternal', server: 'DebugServerId', system_id: int):
        self.client = client
        self.server = server
        self.system_id = system_id

    @property
    def client(self) -> 'DebugClientInternal':
        return self._client

    @property
    def server(self) -> 'DebugServerId':
        return self._server

    @property
    def system_id(self) -> int:
        return self._system_id

    def get_system_id(self) -> int:
        return self.system_id

    def get_full_description(self, flags: tuple) -> str:
        return self.client.get_process_description(self.server, self.system_id, BitmaskSet(flags))

    def get_executable_name(self, flags: tuple) -> str:
        description = self.get_full_description(flags)
        return description.executable_name()

    def get_description(self, flags: tuple) -> str:
        description = self.get_full_description(flags)
        return description.description

    def __eq__(self, other):
        if not isinstance(other, DebugRunningProcessImpl):
            return NotImplemented
        return (self.system_id == other.system_id)

    def __lt__(self, other):
        if not isinstance(other, DebugRunningProcessImpl):
            return NotImplemented
        return self.system_id < other.system_id

    def __gt__(self, other):
        if not isinstance(other, DebugRunningProcessImpl):
            return NotImplemented
        return self.system_id > other.system_id

    def __le__(self, other):
        if not isinstance(other, DebugRunningProcessImpl):
            return NotImplemented
        return self.system_id <= other.system_id

    def __ge__(self, other):
        if not isinstance(other, DebugRunningProcessImpl):
            return NotImplemented
        return self.system_id >= other.system_id

    def __hash__(self) -> int:
        return hash(self.system_id)
```
Note that I've used Python's built-in `property` decorator to create read-only properties for the `client`, `server`, and `system_id` attributes. This is equivalent to Java's public final fields.

I've also implemented the comparison methods (`__eq__`, `__lt__`, etc.) using Python's built-in comparison operators, since Python doesn't have a direct equivalent of Java's `compareTo()` method.

Finally, I've used tuple unpacking in the `get_full_description` and other methods to pass multiple arguments as a single tuple.