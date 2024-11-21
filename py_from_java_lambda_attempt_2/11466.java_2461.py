Here is the translation of the given Java code into equivalent Python:

```Python
class Operand:
    def __init__(self, n: str, o: 'OperandValue', off: 'Offset') -> None:
        self.name = n
        self.op = o
        self.offset = off

    def to_string(self, buf: 'MemBuffer', off: int) -> str:
        return self.op.to_string(buf, self.offset.get_offset(buf, off))

    def length(self, buf: 'MemBuffer', off: int) -> int:
        o = self.offset.get_offset(buf, off)
        return self.op.length(buf, o) + o - off

    def get_info(self, buf: 'MemBuffer', off: int) -> 'ConstructorInfo':
        o = self.offset.get_offset(buf, off)
        opinfo = self.op.get_info(buf, o)
        opinfo.add_length(o-off)
        return opinfo

    @property
    def name(self):
        return self.name

    def link_relative_offsets(self, op_hash: dict) -> None:
        if isinstance(self.op, BinaryExpression):
            (self.op).link_relative_offsets(op_hash)
        else:
            self.offset.set_relative_offset(op_hash)

    def get_handle(self, pcode: list['PcodeOp'], position: 'Position', off: int) -> 'Handle':
        handle = self.op.get_handle(pcode, position, self.offset.get_offset(position.buffer(), off))
        self.test_dynamic()
        return handle

    @property
    def dynamic(self):
        if not hasattr(self, '_dynamic'):
            if self.handle is None:
                self._dynamic = False
            else:
                self._dynamic = self.handle.dynamic()
        return self._dynamic

    def test_dynamic(self) -> None:
        if self.handle is not None:
            self._dynamic = self.handle.dynamic()
        else:
            self._dynamic = False

    @property
    def handle(self):
        return self._handle

    def get_handle(self, position: 'Position', off: int) -> 'Handle':
        if not hasattr(self, '_handle'):
            self._handle = self.op.get_handle(position, self.offset.get_offset(position.buffer(), off))
        return self.handle

    @property
    def handle_list(self):
        return self._handles

    def get_all_handles(self, handles: list['Handle'], position: 'Position', off: int) -> None:
        if not hasattr(self, '_handles'):
            self.op.get_all_handles(handles, position, self.offset.get_offset(position.buffer(), off))
        else:
            for handle in self.handle_list:
                handles.append(handle)

    def get_pcode(self, position: 'Position') -> list['PcodeOp']:
        pcode = []
        self.get_handle(pcode, position, 0)
        return pcode

    @property
    def size(self):
        return self.op.size()

    def to_list(self, list: list['Handle'], position: 'Position', off: int) -> None:
        self.op.to_list(list, position, self.offset.get_offset(position.buffer(), off))
```

Please note that Python does not support Java's `Serializable` interface or the equivalent concept.