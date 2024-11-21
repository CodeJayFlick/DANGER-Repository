Here is the translation of the given Java code into equivalent Python:

```Python
class VarnodeTemplate:
    def __init__(self,
                 space: 'ConstantTemplate',
                 offset: 'ConstantTemplate',
                 size: 'ConstantTemplate',
                 address_factory: 'AddressFactory',
                 oneuse: bool) -> None:
        self.space = space
        self.offset = offset
        self.size = size
        self.address_factory = address_factory
        self.oneuse = oneuse
        self._hash_code = hash((space, offset, size))
        if oneuse:
            self._hash_code += 1

    def set_def(self, op_template: 'OpTemplate') -> None:
        pass

    def resolve(self,
                 handles: dict,
                 position: int,
                 bufoff: int) -> Varnode:
        space_id = -1
        sz = -1
        off = 0

        if self.replace is not None and not self.replace.dynamic():
            handle = self.replace.get_handle()
            space_id = int(handle[Handle.SPACE, 0])
            off = long(handle[Handle.OFFSET, Handle.OFFSET])
            sz = int(handle[Handle.SIZE, 0])

        else:
            space_id = int(self.space.resolve(handles, position, bufoff))
            off = long(self.offset.resolve(handles, position, bufoff))
            sz = int(self.size.resolve(handles, position, bufoff))

        addr = self.get_masked_addr(space_id, off)
        return Varnode(addr, sz)

    def resolve_position_bufoff(self,
                                 position: int,
                                 bufoff: int) -> Varnode:
        space_id = int(self.space.resolve(position, bufoff))
        off = long(self.offset.resolve(position, bufoff))
        sz = int(self.size.resolve(position, bufoff))

        addr = self.get_masked_addr(space_id, off)
        return Varnode(addr, sz)

    def get_masked_addr(self,
                         space_id: int,
                         off: int) -> Address:
        my_space = self.address_factory.get_address_space(space_id)
        return my_space.get_truncated_address(off, False)

    @property
    def oneuse(self):
        return self.oneuse

    @property
    def space(self):
        return self.space

    @property
    def offset(self):
        return self.offset

    @property
    def size(self):
        return self.size

    def set_replace(self, op: 'Operand', load: bool) -> None:
        if load:
            self.loadomit = True
        else:
            self.replace = op

    @property
    def loadomit(self):
        return self.loadomit

    def __hash__(self):
        return self._hash_code

    def __eq__(self, other):
        if not isinstance(other, VarnodeTemplate):
            return False

        if hash((self.space, self.offset, self.size)) != self._hash_code:
            return False
        if self.oneuse is not oneuse:
            return False
        return True


class Address:
    pass


class ConstantTemplate:
    def resolve(self,
                 handles: dict,
                 position: int,
                 bufoff: int) -> int:
        raise NotImplementedError

    @property
    def dynamic(self):
        raise NotImplementedError


class Operand:
    def get_handle(self) -> 'Handle':
        raise NotImplementedError


class Handle:
    OFFSET = 0
    SIZE = 1
    SPACE = 2

    pass


class Varnode:
    def __init__(self, addr: Address, sz: int):
        self.addr = addr
        self.sz = sz


class OpTemplate:
    pass


class Position:
    pass


class AddressFactory:
    def get_address_space(self, space_id: int) -> 'Address':
        raise NotImplementedError

    @property
    def truncated_address(self, off: int, mask: bool):
        raise NotImplementedError
```

Note that Python does not have direct equivalent of Java's `HashMap` and other classes. The above code is a translation into Python syntax but may require further modification to be fully functional in the context you are using it.