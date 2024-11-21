class Ext4Analyzer:
    def __init__(self):
        self.block_size = None

    def get_name(self):
        return "Ext4 Analyzer"

    def get_default_enablement(self, program):
        return True

    def get_description(self):
        return "Annotates Ext4 file systems."

    def can_analyze(self, program):
        provider = MemoryByteProvider(program.memory(), program.address_factory().get_default_address_space())
        reader = BinaryReader(provider, True)
        start = self.get_super_block_start(reader)
        if start == -1:
            return False

        reader.set_pointer_index(start + 0x38)
        magic = None
        try:
            magic = reader.read_next_short()
        except Exception as e:
            pass
        if magic != 0xef53:
            return False
        return True

    def is_prototype(self):
        return False

    def analyze(self, program, set, monitor, log) -> bool:
        provider = MemoryByteProvider(program.memory(), program.address_factory().get_default_address_space())
        reader = BinaryReader(provider, True)
        start = self.get_super_block_start(reader)
        group_start = 0
        reader.set_pointer_index(start)
        super_block = Ext4SuperBlock(reader)
        create_data(program, to_addr(program, start), super_block.to_data_type())

        is_64_bit = (super_block.get_s_desc_size() > 32) and ((super_block.get_s_feature_incompat() & 0x80) > 0)
        num_bytes = program.max_address().get_offset() - program.min_address().get_offset() + 1
        group_size = self.calculate_group_size(super_block)
        num_groups = int(num_bytes / group_size)
        if num_bytes % group_size != 0:
            num_groups += 1

        group_desc_offset = group_start + self.block_size
        address = to_addr(program, group_desc_offset)
        reader.set_pointer_index(group_desc_offset)
        group_descriptors = [Ext4GroupDescriptor(reader, is_64_bit) for _ in range(num_groups)]
        monitor.set_message("Creating group descriptors...")
        monitor.set_maximum(len(group_descriptors))
        for i, descriptor in enumerate(group_descriptors):
            monitor.check_canceled()
            create_data(program, address, descriptor.to_data_type())
            address = address.add(descriptor.to_data_type().get_length())
            monitor.increment_progress(1)

        is_sparse_super = (super_block.get_s_feature_ro_compat() & 1) != 0
        self.create_super_block_copies(program, reader, group_size, num_groups, is_64_bit, is_sparse_super, monitor)
        self.create_inode_tables(program, reader, super_block, group_descriptors, is_64_bit, monitor)

    def create_inode_tables(self, program, reader, super_block, group_descriptors, is_64_bit, monitor):
        inode_count = super_block.get_s_inodes_count()
        inodes = [Ext4Inode(reader) for _ in range(inode_count)]

        for i, descriptor in enumerate(group_descriptors):
            monitor.check_canceled()
            long offset = descriptor.bg_inode_table_lo() & 0xffffffffL
            if is_64_bit:
                offset = (descriptor.bg_inode_table_hi() << 32) | offset
            reader.set_pointer_index(offset)
            address = to_addr(program, offset)

            for j in range(len(inodes)):
                monitor.check_canceled()
                inode = inodes[j]
                short mode = inode.get_i_mode()
                if (mode & Ext4Constants.S_IFDIR) != 0:
                    self.process_directory(program, reader, super_block, inode, monitor)
                elif (mode & Ext4Constants.S_IFREG) != 0:
                    self.process_file(program, reader, super_block, inode, monitor)

    def process_file(self, program, reader, super_block, inode, monitor):
        # TODO?
        pass

    def process_directory(self, program, reader, super_block, inode, monitor):
        if (inode.get_i_flags() & Ext4Constants.EXT4_INDEX_FL) != 0:
            self.process_hash_tree_directory(program, reader, super_block, inode, monitor)
        else:
            # TODO?
            pass

    def process_hash_tree_directory(self, program, reader, super_block, inode, monitor):
        # TODO?
        pass

    def create_super_block_copies(self, program, reader, group_size, num_groups, is_64_bit, is_sparse_super, monitor):
        for i in range(1, num_groups):
            if is_sparse_super and not (is_power_of_y(i, 3) or is_power_of_y(i, 5) or is_power_of_y(i, 7)):
                continue
            offset = group_size * i
            address = to_addr(program, offset)
            reader.set_pointer_index(offset)
            super_block = Ext4SuperBlock(reader)
            create_data(program, address, super_block.to_data_type())

            long group_desc_offset = offset + self.block_size
            address = to_addr(program, group_desc_offset)
            reader.set_pointer_index(group_desc_offset)
            for _ in range(num_groups):
                monitor.check_canceled()
                group_descriptor = Ext4GroupDescriptor(reader, is_64_bit)
                create_data(program, address, group_descriptor.to_data_type())
                address = address.add(group_descriptor.to_data_type().get_length())

    def calculate_group_size(self, super_block):
        log_block_size = super_block.get_s_log_block_size()
        self.block_size = 2 ** (10 + log_block_size)
        return int(super_block.get_s_blocks_per_group() * self.block_size)

    def get_super_block_start(self, reader):
        try:
            padding = -1
            pad_start = 0
            is_padding = False
            while pad_start < 1024:
                if not is_padding:
                    pad_start = int(reader.get_pointer_index())
                padding = reader.read_next_int()
                if padding == 0:
                    if is_padding:
                        return pad_start + 0x400
                    is_padding = True
                else:
                    is_padding = False
        except Exception as e:
            pass
        return -1

    def to_addr(self, program, offset):
        try:
            address = Address(program.memory(), program.address_factory().get_default_address_space())
            address.set_offset(offset)
            return address
        except Exception as e:
            pass
        return None

    @staticmethod
    def is_power_of_y(x, y):
        if x == 0:
            return False
        while x % y == 0:
            x = x // y
        return x == 1


class MemoryByteProvider:
    def __init__(self, memory, address_space):
        self.memory = memory
        self.address_space = address_space

    @staticmethod
    def get_pointer_index(self):
        pass

    @staticmethod
    def read_next_short(self):
        pass

    @staticmethod
    def read_next_int(self):
        pass


class BinaryReader:
    def __init__(self, provider, is_big_endian):
        self.provider = provider
        self.is_big_endian = is_big_endian

    @staticmethod
    def get_pointer_index(self):
        pass

    @staticmethod
    def set_pointer_index(self, offset):
        pass

    @staticmethod
    def read_next_short(self):
        pass

    @staticmethod
    def read_next_int(self):
        pass


class Ext4SuperBlock:
    def __init__(self, reader):
        self.s_desc_size = None
        self.s_feature_incompat = None
        self.s_blocks_per_group = None

    def to_data_type(self):
        # TODO?
        pass


class Ext4GroupDescriptor:
    def __init__(self, reader, is_64_bit):
        self.bg_inode_table_lo = None
        self.bg_inode_table_hi = None

    def to_data_type(self):
        # TODO?
        pass


class Ext4Inode:
    def __init__(self, reader):
        self.i_mode = None
        self.i_flags = None

    def get_i_mode(self):
        return self.i_mode

    def get_i_flags(self):
        return self.i_flags

    @staticmethod
    def read(reader):
        pass


class Ext4Constants:
    S_IFDIR = 0x40000000
    S_IFREG = 0x80000000
    EXT4_INDEX_FL = 0x100
