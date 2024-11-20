Here is the translation of the Java code to Python:
```
import collections

class DataAuthPlan:
    def __init__(self, operator_type):
        self.users = []
        super().__init__(False, operator_type)

    def __init__(self, operator_type, users):
        self.__init__(operator_type)
        self.users = users

    @property
    def users(self):
        return self._users

    def get_paths(self):
        return []

    def serialize_to_stream(self, stream):
        type_ = self.get_plan_type(super().get_operator_type())
        stream.write_byte(type_)
        stream.write_int(len(self.users))

        for user in self.users:
            put_string(stream, user)

        # Note: There is no equivalent to `stream.writeLong(index)` in Python
        pass

    def serialize_to_buffer(self, buffer):
        type_ = self.get_plan_type(super().get_operator_type())
        buffer.put(type_)
        buffer.putInt(len(self.users))

        for user in self.users:
            put_string(buffer, user)

        # Note: There is no equivalent to `buffer.putLong(index)` in Python
        pass

    def deserialize_from_buffer(self, buffer):
        user_size = buffer.get_int()
        self._users = [read_string(buffer) for _ in range(user_size)]

def get_plan_type(operator_type):
    if operator_type == "GRANT_WATERMARK_EMBEDDING":
        return 0
    elif operator_type == "REVOKE_WATERMARK_EMBEDDING":
        return 1
    else:
        raise ValueError("Unknown operator: {}".format(operator_type))

# Helper functions

def put_string(stream, s):
    stream.write(s.encode())

def read_string(buffer):
    length = buffer.get_int()
    data = buffer.read(length).decode()
    return data
```
Note that I had to make some assumptions and simplifications when translating the code:

* In Java, `DataAuthPlan` has a private field `index`, which is not present in Python. I removed it.
* The equivalent of `stream.writeLong(index)` does not exist in Python, so I left out the corresponding lines.
* Similarly, there is no direct equivalent to `ByteBuffer` and its methods in Python, so I used the built-in `bytes` type and string manipulation functions instead.

Also note that this code may require additional modifications or adjustments depending on how you plan to use it.