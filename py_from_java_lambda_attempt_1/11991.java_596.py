Here is the translation of the Java code into Python:

```Python
class MemoryMapDBAdapterV0:
    V0_TABLE_NAME = "Memory Block"
    VERSION = 0

    def __init__(self, handle: 'DBHandle', mem_map: 'MemoryMapDB'):
        self.handle = handle
        self.mem_map = mem_map
        self.blocks = []
        try:
            table = handle.get_table(V0_TABLE_NAME)
            if table is None:
                raise VersionException("Memory Block table not found")
            version_number = table.schema.version()
            if version_number != VERSION:
                raise VersionException(f"Memory Block table: Expected Version {VERSION}, got {version_number}")
            record_count = table.record_count
            self.blocks = [self.create_block(rec) for rec in iter(table)]

        except (VersionException, IOException):
            print("Error occurred")

    def create_block(self, rec):
        permissions = 0
        if rec.get_boolean_value(V0_IS_READ_COL):
            permissions |= MemoryBlock.READ
        if rec.get_boolean_value(V0_IS_WRITE_COL):
            permissions |= MemoryBlock.WRITE
        if rec.get_boolean_value(V0_IS_EXECUTE_COL):
            permissions |= MemoryBlock.EXECUTE

        start_addr = self.mem_map.address_factory.old_get_address_from_long(rec.get_long_value(V0_START_ADDR_COL))
        length = rec.get_long_value(V0_LENGTH_COL)
        buf_id = rec.get_int_value(V0_BUFFER_ID_COL)

        segment = 0
        if VERSION == 1 and isinstance(start_addr, SegmentedAddress):
            segment = rec.get_int_value(V0_SEGMENT_COL)

        block_record = DBRecord()
        sub_block_record = DBRecord()

        block_record.set_string(V0_NAME_COL, rec.get_string(V0_NAME_COL))
        block_record.set_string(V0_COMMENTS_COL, rec.get_string(V0_COMMENTS_COL))
        block_record.set_string(V0_SOURCE_NAME_COL, rec.get_string(V0_SOURCE_NAME_COL))
        block_record.set_byte_value(V0_PERMISSIONS_COL, permissions)
        block_record.set_long_value(V0_START_ADDR_COL, start_addr)
        block_record.set_long_value(V0_LENGTH_COL, length)
        block_record.set_int_value(V0_SEGMENT_COL, segment)

        sub_block_record.set_long_value(SUB_PARENT_ID_COL, 0)
        sub_block_record.set_long_value(SUB_LENGTH_COL, length)
        sub_block_record.set_long_value(SUB_START_OFFSET_COL, 0)

        type = rec.get_short_value(V0_TYPE_COL)
        overlay_addr = rec.get_long_value(V0_BASE_ADDR_COL)
        overlay_addr = self.update_overlay_addr(self.mem_map.address_map, self.mem_map.address_factory, overlay_addr, type)

        sub_block = self.get_sub_block(self.mem_map, buf_id, sub_block_record, type, overlay_addr)

        return MemoryBlockDB(self, block_record, [sub_block])

    def get_sub_block(self, mem_map: 'MemoryMapDB', buf_id: int, record: DBRecord, type: int, overlay_addr: long):
        if type == 0:
            # Bit Mapped
            record.set_byte_value(SUB_TYPE_COL, SUB_ TYPE_BIT_MAPPED)
            record.set_long_value(V2_OVERLAY_ADDR_COL, overlay_addr)
            return BitMappedSubMemoryBlock(self, record)

        elif type == 1:
            # Byte Mapped
            record.set_byte_value(SUB_TYPE_COL, SUB_ TYPE_BYTE_MAPPED)
            record.set_long_value(V2_OVERLAY_ADDR_COL, overlay_addr)
            return ByteMappedSubMemoryBlock(self, record)

        elif type == 2:
            # Initialized
            record.set_byte_value(SUB_TYPE_COL, SUB_ TYPE_BUFFER)
            record.set_long_value(SUB_LONG_DATA2_COL, buf_id)
            return BufferSubMemoryBlock(self, record)

        else:
            raise IOException("Unknown memory block type: " + str(type))

    def update_overlay_addr(self, address_map: 'AddressMap', address_factory: 'AddressFactory', overlay_addr: long, type: int):
        if type == 0 or type == 1:
            addr = address_factory.old_get_address_from_long(overlay_addr)
            overlay_addr = address_map.key(addr, False)

        return overlay_addr

    def refresh_memory(self) -> None:
        pass

    @property
    def memory_blocks(self) -> list:
        return self.blocks

class MemoryBlockDB:
    def __init__(self, adapter: 'MemoryMapDBAdapterV0', block_record: DBRecord, sub_blocks):
        self.adapter = adapter
        self.block_record = block_record
        self.sub_blocks = sub_blocks

# Other methods are not implemented as they were throwing exceptions or unsupported operations