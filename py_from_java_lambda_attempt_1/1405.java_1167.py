Here is a translation of the Java code into equivalent Python:

```Python
class GdbModelTargetMemoryRegion:
    def __init__(self, memory: 'GdbModelTargetProcessMemory', mapping):
        self.range = None
        self.objfile = mapping.get_objfile()
        self.offset = mapping.get_offset()
        self.display = compute_display(mapping)

        super().__init__(memory.impl, memory, key_region(mapping), "MemoryRegion")
        try:
            min_address = memory.impl.get_address_factory().get_default_address_space().get_address(str(mapping.get_start(), 16))
            self.range = AddressRangeImpl(min_address, mapping.get_size())
        except (AddressFormatException, AddressOverflowException) as e:
            raise AssertionError(e)

    def is_same(self, mapping):
        return self.display == compute_display(mapping)

    @property
    def range_(self):
        return self.range

    @property
    def display_(self):
        return self.display

    @property
    def memory_(self):
        return self.parent

    def is_readable(self):
        # It can be done if debugging locally on Linux, by reading /proc/[PID]/maps
        # The sections listing will give the initial protections.
        return True  # TODO

    def is_writable(self):
        return True  # TODO

    def is_executable(self):
        return True  # TODO

    @property
    def objfile_(self):
        return self.objfile

    @property
    def offset_(self):
        return self.offset


def compute_display(mapping):
    if mapping.get_objfile() is None or len(mapping.get_objfile()) == 0:
        return f"?? [0x{mapping.get_start():x}-0x{mapping.get_end():x}]"
    else:
        return f"{mapping.get_objfile()} [0x{mapping.get_start():x}-0x{mapping.get_end():x}] (0x{mapping.get_offset():x})"


def key_region(mapping):
    return PathUtils.make_key(index_region(mapping))


def index_region(mapping):
    return str(mapping.get_start(), 16)


class AddressRangeImpl:
    def __init__(self, min_address, size):
        self.min = min_address
        self.size = size


# Note: The following code is not part of the original Java class.
async def state_changed(sco):
    # Nothing to do here
    return AsyncUtils.NIL

```

This Python translation maintains the same structure and functionality as the original Java code.