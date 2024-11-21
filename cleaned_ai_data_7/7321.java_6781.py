import io


class BTREE_ROOT_NODE_DESCRIPTOR:
    def __init__(self):
        self.header_record = None
        self.user_data_record = None
        self.map_record = None
        self.nodes = []

    def from_binary_reader(self, reader: 'io.BinaryReader') -> None:
        super().__init__()

        self.header_record = BTREE_HEADER_RECORD.from_binary_reader(reader)
        self.user_data_record = BTREE_USER_DATA_RECORD.from_binary_reader(reader)
        self.map_record = BTREE_MAP_RECORD.from_binary_reader(reader, self.header_record)

        nodes.append(self)

        node_size = self.header_record.get_node_size() & 0xffff

        for i in range(node_size, reader.length(), node_size):
            reader.set_pointer_index(i)
            node = BTreeNodeDescriptor()
            nodes.append(node)
            node.read_records(reader, i, self.header_record)
            node.read_record_offsets(reader, i, self.header_record)

    def get_header_record(self) -> 'BTREE_HEADER_RECORD':
        return self.header_record

    def get_user_data_record(self) -> 'BTREE_USER_DATA_RECORD':
        return self.user_data_record

    def get_map_record(self) -> 'BTREE_MAP_RECORD':
        return self.map_record

    def get_node(self, index: int) -> 'BTreeNodeDescriptor' | None:
        try:
            return nodes[index]
        except Exception as e:
            print(f"Error: {e}")
            return None

    def get_nodes(self) -> list['BTreeNodeDescriptor']:
        return self.nodes


class BTREE_HEADER_RECORD:
    pass  # implement your own class for this


class BTREE_USER_DATA_RECORD:
    pass  # implement your own class for this


class BTREE_MAP_RECORD:
    pass  # implement your own class for this
