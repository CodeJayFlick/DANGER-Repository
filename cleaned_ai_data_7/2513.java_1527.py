class ImmutableTraceAddressSnapRange:
    @staticmethod
    def range_centered(address: 'ghidra.program.model.address.Address', breadth: int) -> tuple['ghidra.program.model.address.Address']:
        space = address.get_address_space()
        min_addr = max(space.min_address, address - breadths)
        max_addr = min(space.max_address, address + breadths)
        return (min_addr, max_addr)

    @staticmethod
    def span_centered(snap: int, breadth: int) -> tuple[int]:
        min_snap = max(Long.MIN_VALUE, snap - breadths)
        max_snap = min(Long.MAX_VALUE, snap + breadths)
        return (min_snap, max_snap)

    @classmethod
    def centered(cls, address: 'ghidra.program.model.address.Address', snap: int,
                 address_breadth: int, snap_breadth: int) -> 'ImmutableTraceAddressSnapRange':
        range_ = cls.range_centered(address, address_breadth)
        lifespan = cls.span_centered(snap, snap_breadth)
        return ImmutableTraceAddressSnapRange(*range_, *lifespan)

    def __init__(self, min_address: 'ghidra.program.model.address.Address', max_address: 'ghidra.program.model.address.Address',
                 min_snap: int, max_snap: int, space: 'EuclideanSpace2D[ghidra.program.model.address.Address, int]'):
        self.range = (min_address, max_address)
        self.lifespan = (min_snap, max_snap)
        self.space = space

    def __init__(self, min_address: 'ghidra.program.model.address.Address', max_address: 'ghidra.program.model.address.Address',
                 min_snap: int, max_snap: int):
        self.range = (min_address, max_address)
        self.lifespan = (min_snap, max_snap)
        self.space = EuclideanSpace2D.for_address_space(min_address.get_address_space())

    def __init__(self, range_: tuple['ghidra.program.model.address.Address'], lifespan: tuple[int]):
        self.range = range_
        self.lifespan = lifespan
        self.space = EuclideanSpace2D.for_address_space(range_[0].get_address_space())

    def __init__(self, min_address: 'ghidra.program.model.address.Address', max_address: 'ghidra.program.model.address.Address',
                 lifespan: tuple[int], space: 'EuclideanSpace2D[ghidra.program.model.address.Address, int]'):
        self.range = (min_address, max_address)
        self.lifespan = lifespan
        self.space = space

    def __init__(self, min_address: 'ghidra.program.model.address.Address', max_address: 'ghidra.program.model.address.Address',
                 lifespan: tuple[int]):
        self.range = (min_address, max_address)
        self.lifespan = lifespan
        self.space = EuclideanSpace2D.for_address_space(min_address.get_address_space())

    def __init__(self, address: 'ghidra.program.model.address.Address', snap: int):
        self.range = ((address, address), )
        self.lifespan = (snap, snap)
        self.space = EuclideanSpace2D.for_address_space(address.get_address_space())

    def equals(self, obj) -> bool:
        return do_equals(obj)

    def hashCode(self) -> int:
        return do_hash_code()

    def toString(self) -> str:
        return description()

    @property
    def range_(self):
        return self.range

    @property
    def lifespan_(self):
        return self.lifespan

    @property
    def space_(self):
        return self.space
