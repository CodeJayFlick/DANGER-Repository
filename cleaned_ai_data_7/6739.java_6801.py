class IndexMap:
    def __init__(self):
        self.block_set = ByteBlockSet()
        self.bytes_per_line = 16
        self.num_indexes = BigInteger(0)
        self.block_info_map = {}
        self.next_start_index = BigInteger(0)

    def get_num_indexes(self):
        return self.num_indexes

    def get_bytes_per_line(self):
        return int(self.bytes_per_line)


class ByteBlockSet:
    def __init__(self):
        pass


class BlockInfo:
    def __init__(self, block, start_index, block_start, block_end, end_index):
        self.block = block
        self.start_index = start_index
        self.block_start = block_start
        self.block_end = block_end
        self.end_index = end_index


def get_block_info(index_map: IndexMap, index: int) -> BlockInfo:
    for key in sorted(index_map.block_info_map.keys()):
        if index >= key and index < (key + 16):
            return index_map.block_info_map[key]
    return None


class FieldLocation:
    def __init__(self, index, field_num, col):
        self.index = index
        self.field_num = field_num
        self.col = col


def get_field_location(index_map: IndexMap, block: ByteBlock, offset: int) -> FieldLocation:
    for info in index_map.block_info_map.values():
        if info.block == block and 0 <= offset < len(info.block):
            byte_index = (index_map.bytes_per_line * index_map.next_start_index + BigInteger(str(offset)))
            line_offset = byte_index % index_map.bytes_per_line
            field_num = get_field_num(index_map, byte_index // index_map.bytes_per_line)
            col = 0  # TODO: implement column calculation
            return FieldLocation(byte_index // index_map.bytes_per_line, field_num, col)
    return None


def get_field_num(index_map: IndexMap, index: int) -> int:
    for i in range(len(factorys)):
        if factorys[i].get_field(index):
            return i
    return 0


class ByteBlockInfo:
    def __init__(self, block, offset):
        self.block = block
        self.offset = offset


def get_block_info(index_map: IndexMap, index: int) -> ByteBlockInfo:
    for info in index_map.block_info_map.values():
        if info.block_start <= BigInteger(str(index)) < info.block_end:
            return ByteBlockInfo(info.block, (index - info.block_start).intValue())
    return None


def show_separator(index_map: IndexMap, index: int) -> bool:
    return index in index_map.block_info_map.keys()


class FieldFactory:
    def __init__(self):
        pass

    def get_field(self, index: int) -> ByteField:
        # TODO: implement field calculation
        pass


def main():
    factorys = [FieldFactory() for _ in range(16)]
    index_map = IndexMap()
    byte_blocks = index_map.get_blocks_between(ByteBlockInfo(block=ByteBlock(), offset=0), ByteBlockInfo(block=ByteBlock(), offset=100))
    print(byte_blocks)


if __name__ == "__main__":
    main()

