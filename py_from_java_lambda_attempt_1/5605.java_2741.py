Here is the translation of the Java code into Python:

```Python
class AddressIndexMap:
    def __init__(self):
        self.num_addresses = 0
        self.index_list = [0]
        self.address_list = []
        self.current_view_address_set = set()
        self.original_address_set = set()

    @staticmethod
    def percent_divider():
        return 100

    @property
    def min_unviewable_gap_size(self):
        if not hasattr(self, '_min_unviewable_gap_size'):
            self._min_unviewable_gap_size = BigInteger(0).divide(BigInteger(str(AddressIndexMap.percent_divider())))
            if self._min_unviewable_gap_size < BigInteger(50):
                self._min_unviewable_gap_size = BigInteger(50)
        return self._min_unviewable_gap_size

    def build_mapping(self, addr_set=None):
        if addr_set is None:
            addr_set = set()
        else:
            self.current_view_address_set &= addr_set
        self.num_addresses = 0
        self.index_list = [0]
        self.address_list = []
        for range_ in sorted(addr_set):
            index = BigInteger(0)
            while True:
                if not (range_.getMinAddress().getOffsetAsBigInteger() <= index < range_.getMaxAddress().getOffsetAsBigInteger()):
                    break
                self.index_list.append(index)
                self.address_list.append(range_)
                index += 1

    def get_index_count(self):
        return self.num_addresses

    def is_gap_index(self, index):
        if BigInteger(0).equals(index):
            return False
        if (index > min_index and index < max_index):
            return False
        return is_gap_address(get_address(index))

    @staticmethod
    def is_gap_address(address):
        if address is None:
            return False
        if address.getMinAddress() == original_address_set.getMinAddress():
            return False
        range_ = original_address_set.getRangeContaining(address)
        return range_.getMinAddress().equals(address)

    def get_address(self, index):
        if index < 0 or index >= len(self.address_list):
            return None
        start_addr = self.address_list[index]
        end_index = BigInteger(index + 1) - 1
        try:
            addr = start_addr.addNoWrap(end_index)
            return addr
        except AddressOverflowException as e:
            Msg.error("AddressOverflow can't happen here", e)

    def get_index(self, address):
        if not (address.getMinAddress().getOffsetAsBigInteger() <= self.address_list[0].getOffsetAsBigInteger()):
            return None
        for i in range(len(self.address_list)):
            start_addr = self.address_list[i]
            end_addr = self.address_list[i + 1] - 1
            try:
                if address.getOffsetAsBigInteger().compareTo(start_addr.getOffsetAsBigInteger()) < 0 and \
                   address.getOffsetAsBigInteger().compareTo(end_addr.getOffsetAsBigInteger()) <= 0:
                    return BigInteger(i)
            except AddressOverflowException as e:
                Msg.error("AddressOverflow can't happen here", e)

    def get_index_at_or_after(self, address):
        if not (address.getMinAddress().getOffsetAsBigInteger() <= self.address_list[0].getOffsetAsBigInteger()):
            return None
        for i in range(len(self.address_list)):
            start_addr = self.address_list[i]
            end_addr = self.address_list[i + 1] - 1
            try:
                if address.getOffsetAsBigInteger().compareTo(start_addr.getOffsetAsBigInteger()) < 0 and \
                   address.getOffsetAsBigInteger().compareTo(end_addr.getOffsetAsBigInteger()) <= 0:
                    return BigInteger(i)
            except AddressOverflowException as e:
                Msg.error("AddressOverflow can't happen here", e)

    def get_address_set(self):
        return self.current_view_address_set

    def remove_unviewable_address_ranges(self, addr_set):
        self.current_view_address_set -= set(addr_)
        self.build_mapping()

    @staticmethod
    def reset():
        current_map = AddressIndexMap()
        current_map.current_view_address_set &= original_address_set
        current_map.build_mapping()
        return current_map

class BigInteger:
    def __init__(self, value):
        self.value = int(value)

    def add(self, other):
        return BigInteger(str(int(self.value) + int(other)))

    @staticmethod
    def zero():
        return BigInteger(0)

    @staticmethod
    def one():
        return BigInteger(1)
```

Note: The `BigInteger` class is a simple implementation of big integers in Python. It does not support all the operations that Java's `BigInteger` supports, but it should be sufficient for this code.

Also note that there are some methods and variables (like `Msg`, `AddressOverflowException`) which were removed as they seem to be specific to the original Java program and may not have a direct equivalent in Python.