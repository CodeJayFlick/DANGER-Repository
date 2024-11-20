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
