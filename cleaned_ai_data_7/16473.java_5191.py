class RemoveNodeLog:
    def __init__(self):
        self.partition_table = None
        self.removed_node = None
        self.meta_log_index = 0

    def set_partition_table(self, partition_table):
        self.partition_table = partition_table

    def get_partition_table(self):
        return self.partition_table.copy()

    def set_removed_node(self, removed_node):
        self.removed_node = removed_node

    def get_removed_node(self):
        return self.removed_node

    def set_meta_log_index(self, meta_log_index):
        self.meta_log_index = meta_log_index

    def get_meta_log_index(self):
        return self.meta_log_index

    def serialize(self):
        data = bytearray()
        with io.BytesIO() as byte_stream:
            try:
                byte_stream.write(bytearray([0]))  # Types.REMOVE_NODE.ordinal
                byte_stream.write(int_to_bytes(getattr(self, 'curr_log_index')))
                byte_stream.write(int_to_bytes(getattr(self, 'curr_log_term')))
                byte_stream.write(int_to_bytes(self.meta_log_index))

                NodeSerializeUtils.serialize(self.removed_node, byte_stream)

                data.extend(bytearray([0]))  # partition_table.array().length
                data.extend(self.partition_table.raw())

            except Exception as e:
                pass

        return memoryview(data)

    def deserialize(self, buffer):
        self.curr_log_index = int.from_bytes(buffer[4:8], 'big')
        self.curr_log_term = int.from_bytes(buffer[8:12], 'big')
        self.meta_log_index = int.from_bytes(buffer[12:16], 'big')

        self.removed_node = Node()
        NodeSerializeUtils.deserialize(self.removed_node, buffer)

        len_ = int.from_bytes(buffer[16:20], 'big')
        data = memoryview(buffer)[20:]
        self.partition_table = bytearray(data)
