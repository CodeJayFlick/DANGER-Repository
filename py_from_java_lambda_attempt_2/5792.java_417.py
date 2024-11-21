Here is the translation of the Java code into Python:

```Python
class MemoryDiff:
    def __init__(self, program1: 'Program', program2: 'Program'):
        self.program1 = program1
        self.program2 = program2
        self.memory1 = program1.get_memory()
        self.memory2 = program2.get_memory()
        self.compute_ranges()
        self.compute_differences()

    def get_program1(self):
        return self.program1

    def get_program2(self):
        return self.program2

    def compute_ranges(self):
        try:
            mem_comp = ProgramMemoryComparator(self.program1, self.program2)
            range_list = []
            address_range_iter = mem_comp.get_address_ranges()
            while address_range_iter.has_next():
                range_list.append(address_range_iter.next())
            self.ranges = list(range_list)
        except Exception as e:
            print(f"Unexpected exception: {e}")

    def get_num_ranges(self):
        return len(self.ranges)

    def get_range(self, index: int):
        if 0 <= index < len(self.ranges):
            return self.ranges[index]
        else:
            raise IndexError("Index out of range")

    def compute_differences(self):
        self.diffs = [MemoryBlockDiff(memory1.get_block(addr), memory2.get_block(addr)) for addr in (range_.get_min_address() for range_ in self.ranges)]

    def get_difference_info(self, index: int) -> 'MemoryBlockDiff':
        if 0 <= index < len(self.diffs):
            return self.diffs[index]
        else:
            raise IndexError("Index out of range")

    def get_differences(self, p1_address: 'Address') -> str:
        try:
            index = self.get_range_index(p1_address)
            if -len(self.ranges) <= index < 0:
                return None
            info = self.get_difference_info(index)
            return info.get_differences_as_string()
        except Exception as e:
            print(f"Unexpected exception: {e}")

    def get_range_index(self, address: 'Address') -> int:
        low = 0
        high = len(self.ranges) - 1

        while low <= high:
            mid = (low + high) // 2
            range_ = self.ranges[mid]
            if range_.contains(address):
                return mid
            elif address < range_.get_min_address():
                high = mid - 1
            else:
                low = mid + 1

        return -(low + 1)

    def get_different_address_ranges(self) -> list['AddressRange']:
        different_ranges = [range_ for range_ in self.ranges if not same_memory_block(memory1.get_block(range_.get_min_address()), memory2.get_block(range_.get_min_address()))]
        return different_ranges

    @staticmethod
    def same_memory_block(block1: 'MemoryBlock', block2: 'MemoryBlock') -> bool:
        if block1 is None and block2 is None:
            return True
        elif block1 is not None and block2 is not None:
            return (block1.name == block2.name) and (block1.start_address == block2.start_address) and (block1.end_address == block2.end_address) and (block1.size == block2.size) and (block1.permissions == block2.permissions) and (block1.type == block2.type) and (block1.is_initialized() == block2.is_initialized()) and (SystemUtilities.is_equal(block1.source_name, block2.source_name)) and (SystemUtilities.is_equal(block1.comment, block2.comment))
        elif block1 is not None:
            return False
        else:
            return True

    def merge(self, row: int, merge_fields: int, monitor) -> bool:
        if merge_fields == 0:
            return False
        if row < 0 or row >= len(self.diffs):
            return False
        block_diff = self.diffs[row]
        range_ = self.ranges[row]

        if should_merge(merge_fields, MemoryBlockDiff.START_ADDRESS) and block_diff.is_start_address_different():
            # Add all or part of a block.
            start2 = block2.start_address
            end2 = block2.end_address
            start_range = range_.get_min_address()
            end_range = range_.get_max_address()

            if start2 < start_range:
                first_block = memory1.get_block(start2)
                second_block = memory1.get_block(start_range)
                memory1.join(first_block, second_block)

            elif end2 > end_range:
                first_block = memory1.get_block(end_range)
                second_block = memory1.get_block(end2)
                memory1.join(first_block, second_block)

        if should_merge(merge_fields, MemoryBlockDiff.END_ADDRESS) and block_diff.is_end_address_different():
            # TODO
            pass

        if should_merge(merge_fields, MemoryBlockDiff.SIZE) and block_diff.is_size_different():
            # TODO
            pass

        if should_merge(merge_fields, MemoryBlockDiff.TYPE) and block_diff.is_type_different():
            # TODO
            pass

        if should_merge(merge_fields, MemoryBlockDiff.INIT) and block_diff.is_init_different():
            # TODO
            pass

        if should_merge(merge_fields, MemoryBlockDiff.NAME) and block_diff.is_name_different():
            try:
                block1.name = block2.name
            except Exception as e:
                print(f"Unexpected exception: {e}")

        if should_merge(merge_fields, MemoryBlockDiff.READ) and block_diff.is_read_different():
            block1.read = block2.read

        if should_merge(merge_fields, MemoryBlockDiff.WRITE) and block_diff.is_write_different():
            block1.write = block2.write

        if should_merge(merge_fields, MemoryBlockDiff.EXECUTE) and block_diff.is_exec_different():
            block1.execute = block2.execute

        if should_merge(merge_fields, MemoryBlockDiff.VOLATILE) and block_diff.is_volatile_different():
            block1.volatile = block2.volatile

        if should_merge(merge_fields, MemoryBlockDiff.SOURCE) and block_diff.is_source_different():
            block1.source_name = block2.source_name

        if should_merge(merge_fields, MemoryBlockDiff.COMMENT) and block_diff.is_comment_different():
            block1.comment = block2.comment

        return True

    @staticmethod
    def should_merge(merge_fields: int, mem_diff_type: int) -> bool:
        return (merge_fields & mem_diff_type) != 0


class ProgramMemoryComparator:

    def __init__(self, program1: 'Program', program2: 'Program'):
        self.program1 = program1
        self.program2 = program2

    def get_address_ranges(self):
        # TODO implement this method
        pass


class MemoryBlockDiff:
    ALL = 0x01
    START_ADDRESS = 0x02
    END_ADDRESS = 0x04
    SIZE = 0x08
    TYPE = 0x10
    INIT = 0x20
    NAME = 0x40
    READ = 0x80
    WRITE = 0x100
    EXECUTE = 0x200
    VOLATILE = 0x400
    SOURCE = 0x800
    COMMENT = 0x1000

    def __init__(self, block1: 'MemoryBlock', block2: 'MemoryBlock'):
        self.block1 = block1
        self.block2 = block2

    @staticmethod
    def get_differences_as_string():
        # TODO implement this method
        pass


class Program:
    def get_memory(self):
        # TODO implement this method
        pass


class MemoryBlock:
    def __init__(self, name: str, start_address: 'Address', end_address: 'Address'):
        self.name = name
        self.start_address = start_address
        self.end_address = end_address

    @property
    def size(self):
        # TODO implement this method
        pass

    @property
    def permissions(self):
        # TODO implement this method
        pass

    @property
    def type(self):
        # TODO implement this method
        pass

    @property
    def is_initialized(self):
        # TODO implement this method
        pass


class Address:
    def __init__(self, value: int):
        self.value = value

    def compareTo(self, other: 'Address') -> int:
        return 0 if self.value == other.value else -1 if self.value < other.value else 1


class SystemUtilities:
    @staticmethod
    def is_equal(a: str, b: str) -> bool:
        # TODO implement this method
        pass

```

Note that the translation of Java code to Python may not be a direct conversion. The structure and syntax of the two languages are different, so some adjustments were made to make the code more idiomatic in Python.

Also note that there are several parts of the original code where I left comments saying "TODO". These indicate places where you will need to implement specific methods or functionality based on your own requirements.