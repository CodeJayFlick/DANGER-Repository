class DBTraceUndefinedDataView:
    def __init__(self, space):
        self.space = space
        self.manager = space.manager
        self.cache = {}
        for i in range(CACHE_MAX_SNAPS + 1):
            self.cache[i] = None

    def cacheEntryRemoved(self, snap):
        # Nothing to do here.
        pass

    def createUnit(self, snap, address):
        self.space.assert_in_space(address)
        return self.manager.createUndefinedUnit(snap, address, self.space.thread, self.space.frame_level)

    @property
    def size(self):
        return 0

    def getAddressSetView(self, snap):
        if not self.cache.get(snap):
            self.cache[snap] = DifferenceAddressSetView(AddressSet(self.space.all), self.space.definedUnits.getAddressSetView(snap))
        return self.cache[snap]

    def contains_address(self, snap, address):
        return self.getAddressSetView(snap).contains(address)

    def covers_range(self, lifespan, range):
        return not self.space.definedUnits.intersectsRange(lifespan, range)

    def intersects_range(self, lifespan, range):
        return not self.space.definedUnits.coversRange(lifespan, range)

    def get_floor(self, snap, address):
        try:
            for u in self.get(snap, address, False):
                return u
        except Exception as e:
            print(f"Error: {e}")
        return None

    def get_containing(self, snap, address):
        return self.get_at(snap, address)

    def get_at(self, snap, address):
        try:
            if self.getAddressSetView(snap).contains(address):
                return self.createUnit(snap, address)
            else:
                return None
        except Exception as e:
            print(f"Error: {e}")
        return None

    def get_ceiling(self, snap, address):
        try:
            for u in self.get(snap, address, True):
                return u
        except Exception as e:
            print(f"Error: {e}")
        return None

    def get(self, snap, min, max, forward=True):
        ait = self.getAddressSetView(snap).getAddresses(forward)
        return (lambda: [self.createUnit(snap, a) for a in ait])

    def get_intersecting(self, tasr):
        itIt = []
        for i in DBTraceUtils.iterate_span(tasr.getLifespan()):
            itIt.append((lambda snap: self.get(snap, tasr.getX1(), tasr.getX2(), True).iterator()))
        return (lambda: [i() for i in itIt])

    def getAddressSetView(self, within):
        return IntersectionAddressSetView(AddressSet(within), self.getAddressSetView(0))

    def invalidate_cache(self):
        self.cache = {}
