class AddressRangeIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def iterator(self) -> 'AddressRangeIterator':
        return self


class WrappingAddressRangeIterator(AddressRangeIterator):
    def __init__(self, it: Iterator['AddressRange']):
        super().__init__()
        self.it = it

    def has_next(self) -> bool:
        return self.it.has_next()

    def next(self) -> 'AddressRange':
        return self.it.next()

    def iterator(self) -> 'WrappingAddressRangeIterator':
        return self


def cast_or_wrap(it: Iterator['AddressRange']) -> AddressRangeIterator:
    if isinstance(it, AddressRangeIterator):
        return it
    else:
        return WrappingAddressRangeIterator(it)


class UnionAddressRangeIterator(AddressRangeIterator):
    def __init__(self, iterators: Collection[Iterator['AddressRange']], forward: bool):
        super().__init__()
        self.iterators = iterators
        self.forward = forward

    def has_next(self) -> bool:
        for it in self.iterators:
            if it.has_next():
                return True
        return False

    def next(self) -> 'AddressRange':
        iterator = None
        for it in self.iterators:
            if it.has_next():
                iterator = it
                break
        if not self.forward and isinstance(iterator, WrappingAddressRangeIterator):
            while iterator.it.hasNext() and iterator.next().getMinAddress() <= 0:
                pass
        return iterator.next()

    def iterator(self) -> 'UnionAddressRangeIterator':
        return self


def do_check_start(range: AddressRange, start: int, forward: bool) -> bool:
    if start is None:
        return True
    if forward:
        return range.getMaxAddress() >= start
    else:
        return range.getMinAddress() <= start


class SubtractAddressRangeIterator(AddressRangeIterator):
    def __init__(self, a: Iterator['AddressRange'], b: Iterator['AddressRange'], start: int, forward: bool):
        super().__init__()
        self.a = a
        self.b = b
        self.start = start
        self.forward = forward

    def has_next(self) -> bool:
        return next((it for it in (self.a, self.b) if it.has_next()), None) is not None

    def next(self) -> 'AddressRange':
        iterator = None
        for it in (self.a, self.b):
            while it.hasNext():
                address_range = it.next()
                if do_check_start(address_range, self.start, self.forward):
                    return address_range
        raise StopIteration


def subtract(a: Iterator['AddressRange'], b: Iterator['AddressRange'], start: int, forward: bool) -> AddressRangeIterator:
    return SubtractAddressRangeIterator(Iterators.transform(
        Iterators.filter(TwoWayBreakdownAddressRangeIterator(a, b, forward), lambda e: do_check_start(e[0], start, forward)),
        lambda e: e[0]), a.get(), b)


class XorAddressRangeIterator(AddressRangeIterator):
    def __init__(self, a: Iterator['AddressRange'], b: Iterator['AddressRange'], start: int, forward: bool):
        super().__init__()
        self.a = a
        self.b = b
        self.start = start
        self.forward = forward

    def has_next(self) -> bool:
        return next((it for it in (self.a, self.b) if it.has_next()), None) is not None

    def next(self) -> 'AddressRange':
        iterator = None
        for it in (self.a, self.b):
            while it.hasNext():
                address_range, which = it.next()
                if do_check_start(address_range, self.start, self.forward) and which.inXor():
                    return address_range
        raise StopIteration


def xor(a: Iterator['AddressRange'], b: Iterator['AddressRange'], start: int, forward: bool) -> AddressRangeIterator:
    eit = TwoWayBreakdownAddressRangeIterator(a, b, forward)
    fit = Iterators.filter(eit, lambda e: e[1].inXor())
    rit = Iterators.transform(fit, lambda e: e[0])
    uit = UnionAddressRangeIterator(rit, self.forward)
    result = Iterators.filter(uit, lambda r: do_check_start(r, start, forward))
    return WrappingAddressRangeIterator(result)


class IntersectAddressRangeIterator(AddressRangeIterator):
    def __init__(self, a: Iterator['AddressRange'], b: Iterator['AddressRange'], forward: bool):
        super().__init__()
        self.a = a
        self.b = b
        self.forward = forward

    def has_next(self) -> bool:
        return next((it for it in (self.a, self.b) if it.has_next()), None) is not None

    def next(self) -> 'AddressRange':
        iterator = None
        for it in (self.a, self.b):
            while it.hasNext():
                address_range, which = it.next()
                if do_check_start(address_range, start, forward) and which.inIntersect():
                    return address_range
        raise StopIteration


def intersect(a: Iterator['AddressRange'], b: Iterator['AddressRange'], forward: bool) -> AddressRangeIterator:
    return WrappingAddressRangeIterator(Iterators.transform(
        Iterators.filter(TwoWayBreakdownAddressRangeIterator(a, b, forward), lambda e: e[1].inIntersect()),
        lambda e: e[0]))
