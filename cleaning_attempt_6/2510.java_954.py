class DefaultAddressSnap:
    def __init__(self, address: 'ghidra.program.model.address.Address', snap: int):
        self._address = address
        self._snap = snap

    @property
    def address(self) -> 'ghidra.program.model.address.Address':
        return self._address

    @property
    def snap(self) -> int:
        return self._snap

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, DefaultAddressSnap):
            return False
        else:
            that = other
            if self.address != that.address:
                return False
            if self.snap != that.snap:
                return False
            return True

    def __hash__(self) -> int:
        return hash((self._address, self._snap))

    def __lt__(self, other):
        if self is other:
            return False
        else:
            result = self.address.__lt__(other.get_address())
            if result:
                return result
            result = self.snap - other.get_snap()
            if result < 0:
                return True
            elif result > 0:
                return False
            return self._address.__eq__(other.get_address())

    def __le__(self, other):
        return self.__lt__(other) or self == other

    def __gt__(self, other):
        if not (self < other or self == other):
            result = self.address.__gt__(other.get_address())
            if result:
                return True
            else:
                result = self.snap - other.get_snap()
                if result > 0:
                    return True
                elif result < 0:
                    return False
                return not (self._address == other.get_address())

    def __ge__(self, other):
        return not (self < other)
