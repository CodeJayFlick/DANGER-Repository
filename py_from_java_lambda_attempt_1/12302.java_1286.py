Here is the translation of the given Java code into Python:

```Python
class EnumValuePartitioner:
    @staticmethod
    def merge(bit_groups, bit_group):
        for group in list(bit_groups):
            if bit_group.intersects(group):
                bit_group.merge(group)
                bit_groups.remove(group)
        bit_groups.append(bit_group)

    @staticmethod
    def partition(values, size):
        bit_groups = []
        total_mask = 0
        for value in values:
            total_mask |= value
            bit_group = BitGroup(value)
            EnumValuePartitioner.merge(bit_groups, bit_group)
        
        # now create a BitGroup for all bits not accounted for
        enum_mask = ~(1 << (size * 8))
        bit_groups.append(BitGroup(~total_mask & enum_mask))

        return bit_groups


class BitGroup:
    def __init__(self, value):
        self.value = value

    def intersects(self, other):
        # This method should be implemented based on the actual implementation in Java
        pass

    def merge(self, other):
        # This method should be implemented based on the actual implementation in Java
        pass


# Example usage:
values = [1, 2, 3]
size = 4
bit_groups = EnumValuePartitioner.partition(values, size)
print(bit_groups)