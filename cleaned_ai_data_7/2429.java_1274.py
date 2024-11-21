class DBTraceProgramViewFragment:
    def __init__(self, listing: 'AbstractDBTraceProgramViewListing', region: 'DBTraceMemoryRegion'):
        self.listing = listing
        self.region = region

    def get_comment(self):
        return self.region.description()

    def set_comment(self, comment):
        raise UnsupportedOperationException()

    @property
    def name(self):
        return self.region.name

    @name.setter
    def name(self, value):
        if not isinstance(value, str):
            raise TypeError('Name must be a string')
        try:
            self.listing.root_module.setName(value)
        except DuplicateNameException as e:
            raise ValueError(f"Duplicate Name: {e}")

    def get_num_parents(self):
        return 1

    @property
    def parents(self):
        return [self.listing.root_module]

    @property
    def parent_names(self):
        return ['AbstractDBTraceProgramViewListing.TREE_NAME']

    @property
    def tree_name(self):
        return 'AbstractDBTraceProgramViewListing.TREE_NAME'

    def contains(self, addr: 'Address'):
        return self.region.contains(addr, self.listing.program.snap)

    def contains(self, start: 'Address', end: 'Address'):
        snap = self.listing.program.snap
        return (self.region.contains(start, snap) and 
                self.region.contains(end, snap))

    def contains(self, range_set: 'AddressSetView'):
        for addr_range in range_set:
            if not (self.region.contains(addr_range.min_address, self.listing.program.snap) and 
                    self.region.contains(addr_range.max_address, self.listing.program.snap)):
                return False
        return True

    def to_address_set(self):
        return AddressSet(self.region.min_address, self.region.max_address)

    @property
    def is_empty(self):
        return False

    @property
    def min_address(self):
        return self.region.min_address

    @property
    def max_address(self):
        return self.region.max_address

    def get_num_address_ranges(self):
        return 1

    def get_address_ranges(self, forward: bool = True):
        return self.to_address_set().get_address_ranges(forward)

    def get_address_ranges(self, start: 'Address', forward: bool = True):
        return self.to_address_set().get_address_ranges(start, forward)

    def __iter__(self):
        return iter(self.to_address_set())

    @property
    def num_addresses(self):
        return self.to_address_set().num_addresses

    def get_addresses(self, forward: bool = True):
        return self.to_address_set().get_addresses(forward)

    def get_addresses(self, start: 'Address', forward: bool = True):
        return self.to_address_set().get_addresses(start, forward)

    @property
    def intersects(self, addr_set_view: 'AddressSetView'):
        return self.to_address_set().intersects(addr_set_view)

    @property
    def intersects_range(self, start: 'Address', end: 'Address'):
        return self.to_address_set().intersects_range(start, end)

    def intersect(self, view: 'AddressSetView'):
        return self.to_address_set().intersect(view)

    def intersect_range(self, start: 'Address', end: 'Address'):
        return self.to_address_set().intersect_range(start, end)

    @property
    def union(self, addr_set_view: 'AddressSetView'):
        return self.to_address_set().union(addr_set_view)

    @property
    def subtract(self, addr_set_view: 'AddressSetView'):
        return self.to_address_set().subtract(addr_set_view)

    @property
    def xor(self, addr_set_view: 'AddressSetView'):
        return self.to_address_set().xor(addr_set_view)

    @property
    def has_same_addresses(self, view: 'AddressSetView'):
        return self.to_address_set().has_same_addresses(view)

    @property
    def first_range(self):
        return AddressRangeImpl(self.region.min_address, self.region.max_address)

    @property
    def last_range(self):
        return AddressRangeImpl(self.region.min_address, self.region.max_address)

    def get_range_containing(self, address: 'Address'):
        if self.contains(address):
            return self.first_range
        else:
            return None

    def find_first_address_in_common(self, set_view: 'AddressSetView'):
        return self.to_address_set().find_first_address_in_common(set_view)

    @property
    def contains_code_unit(self, code_unit: 'CodeUnit'):
        return self.contains(code_unit.min_address, code_unit.max_address)

    def get_code_units(self):
        return self.listing.get_code_units(self.to_address_set(), True)
