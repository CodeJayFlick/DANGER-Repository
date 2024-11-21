class AddNodeLog:
    def __init__(self):
        self.partition_table = None
        self.new_node = None
        self.meta_log_index = 0

    @property
    def partition_table(self):
        return self._partition_table

    @partition_table.setter
    def partition_table(self, value):
        self._partition_table = value

    @property
    def new_node(self):
        return self._new_node

    @new_node.setter
    def new_node(self, value):
        self._new_node = value

    @property
    def meta_log_index(self):
        return self._meta_log_index

    @meta_log_index.setter
    def meta_log_index(self, value):
        self._meta_log_index = value

    def serialize(self):
        data = bytearray()
        with io.BytesIO() as f:
            f.write(bytearray([1]))  # marker for ADD_NODE type
            f.write(int_to_bytes(self.curr_log_index))
            f.write(int_to_bytes(self.curr_log_term))
            f.write(int_to_bytes(self.meta_log_index))

            self.new_node.serialize(f)

            len = int.from_bytes(f.read(4), 'big')
            data += f.read(len)
        return bytes(data)

    def deserialize(self, buffer):
        pos = 0
        set_curr_log_index(int.from_bytes(buffer[pos:pos+8], 'big'))
        set_curr_log_term(int.from_bytes(buffer[pos+8:pos+16], 'big'))
        self.meta_log_index = int.from_bytes(buffer[pos+16:pos+24], 'big')

        new_node = Node()
        new_node.deserialize(buffer, pos=24)

        len = int.from_bytes(buffer[pos+48:pos+52], 'big')
        data = buffer[pos+52:pos+52+len]
        self.partition_table = memoryview(data).tobytes()

    def __eq__(self, other):
        if not isinstance(other, AddNodeLog):
            return False
        return (super().__eq__(other) and 
                self.new_node == other.new_node and 
                self.partition_table == other.partition_table)

    def __str__(self):
        return f"AddNodeLog{{'new_node': {self.new_node}, 'partition_table': {self.partition_table}}}"

def int_to_bytes(n, length=4):
    result = bytearray(length)
    for i in range(length)[::-1]:
        result[i] = (n >> (i * 8)) & 0xFF
    return bytes(result)

class Node:
    def __init__(self):
        pass

    @property
    def serialize(self, f):
        # implement serialization logic here
        pass

    @classmethod
    def deserialize(cls, buffer, pos=0):
        # implement deserialization logic here
        pass
