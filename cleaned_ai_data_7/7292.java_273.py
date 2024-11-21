class Ext4GroupDescriptor:
    def __init__(self, provider, is64Bit):
        self.is64Bit = is64Bit
        
        if not is64Bit:
            return
        
        bg_block_bitmap_lo = int.from_bytes(provider.read(4), 'little')
        bg_inode_bitmap_lo = int.from_bytes(provider.read(4), 'little')
        bg_inode_table_lo = int.from_bytes(provider.read(4), 'little')
        bg_free_blocks_count_lo = provider.readShort()
        bg_free_inodes_count_lo = provider.readShort()
        bg_used_dirs_count_lo = provider.readShort()
        bg_flags = provider.readShort()
        bg_exclude_bitmap_lo = int.from_bytes(provider.read(4), 'little')
        bg_block_bitmap_csum_lo = provider.readShort()
        bg_inode_bitmap_csum_lo = provider.readShort()
        bg_itable_unused_lo = provider.readShort()
        bg_checksum = provider.readShort()

    def get_bg_block_bitmap_lo(self):
        return self.bg_block_bitmap_lo

    def get_bg_inode_bitmap_lo(self):
        return self.bg_inode_bitmap_lo

    # ... (rest of the methods)

    @property
    def bg_inode_table(self):
        if not self.is64Bit:
            raise ValueError("bg_ inode table is only available in 64-bit mode")
        return ((self.bg_inode_table_hi << 32) | int.from_bytes(self.bg_inode_table_lo.to_bytes(4, 'little'), 'little'))

# ... (rest of the class)
