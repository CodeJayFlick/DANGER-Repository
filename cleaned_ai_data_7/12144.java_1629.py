class AddressMapImpl:
    ADDR_OFFSET_SIZE = 32
    MAP_ID_SIZE = 8
    MAX_OFFSET = (1 << ADDR_OFFSET_SIZE) - 1
    ADDR_OFFSET_MASK = MAX_OFFSET
    MAP_ID_MASK = -(1 << (64 - MAP_ID_SIZE))
    BASE_MASK = ~ADDR_OFFSET_MASK
    BASE_ID_SIZE = 64 - MAP_ID_SIZE - ADDR_OFFSET_SIZE
    BASE_ID_MASK = (1 << BASE_ID_SIZE) - 1

    STACK_SPACE_ID = -1 >> MAP_ID_SIZE

    def __init__(self):
        self.spaceMap = {}
        self.stackSpace = None
        self.addrFactory = None
        self.baseAddrs = []
        self.sortedBaseStartAddrs = []
        self.sortedBaseEndAddrs = []
        self.addrToIndexMap = {}

    def init(self):
        lastBaseIndex = len(self.baseAddrs) - 1
        sortedBaseEndAddrs = [self.baseAddrs[i] for i in range(len(self.baseAddrs))]
        Arrays.sort(sortedBaseStartAddrs)
        for i, addr in enumerate(sortedBaseStartAddrs):
            max_offset = min(addr.getOffset(), MAX_OFFSET)
            off = addr.getOffset() | max_offset
            sortedBaseEndAddrs[i] = self.addrFactory.getAddressInThisSpaceOnly(off)

    def getBaseAddressIndex(self, addr):
        if addr.getAddressSpace().isStackSpace():
            return STACK_SPACE_ID

        baseOffset = addr.getOffset() & BASE_MASK
        for i in range(len(sortedBaseStartAddrs)):
            if sortedBaseStartAddrs[i].hasSameAddressSpace(addr) and baseOffset == sortedBaseStartAddrs[i].getOffset():
                return lastBaseIndex
        index = binary_search(sortedBaseStartAddrs, addr)
        if index < 0:
            index = -index - 2

    def checkAddressSpace(self, space):
        name = space.getName()
        existing_space = self.spaceMap.get(name)
        if not existing_space:
            self.spaceMap[name] = space
        elif not space.equals(existing_space):
            raise ValueError("Address space conflicts with another space in map")

    def decodeAddress(self, value):
        if (value & MAP_ID_MASK) != self.mapIdBits:
            return Address.NO_ADDRESS

        baseIndex = (int)(value >> ADDR_OFFSET_SIZE) & BASE_ID_MASK
        offset = value & ADDR_OFFSET_MASK
        if baseIndex == STACK_SPACE_ID and self.stackSpace is not None:
            return self.stackSpace.getAddress((int)offset)

    def getKey(self, addr):
        return self.mapIdBits | ((long)(self.getBaseAddressIndex(addr)) << ADDR_OFFSET_SIZE) | (addr.getOffset() & ADDR_OFFSET_MASK)

    def findKeyRange(self, key_range_list, addr):
        if addr is None:
            return -1
        index = binary_search(key_range_list, addr)
        if index < 0:
            index = -index - 2

    def getKeyRanges(self, start, end):
        if start.getAddressSpace() != end.getAddressSpace():
            raise ValueError()
        keyRangeList = []
        addKeyRanges(keyRangeList, start, end)

    def reconcile(self):
        remapSpaces = {}
        for space in self.spaceMap.values():
            if isinstance(space, ObsoleteOverlaySpace):
                oldOverlaySpace = (ObsoleteOverlaySpace)space
                curSpace = self.addrFactory.getAddressSpace(oldOverlaySpace.getName())
                if curSpace is not None and curSpace.equals(oldOverlaySpace.getOriginalSpace()):
                    remapSpaces[oldOverlaySpace.getName()] = curSpace
            elif isinstance(space, OverlayAddressSpace):
                AddressSpace curSpace = self.addrFactory.getAddressSpace(space.getName())
                if curSpace is None or not curSpace.equals(space):
                    ObsoleteOverlaySpace obsoleteSpace = ObsoleteOverlaySpace(space)
                    remapSpaces[space.getName()] = obsoleteSpace

        for space in remapSpaces.values():
            self.spaceMap[space.getName()] = space
