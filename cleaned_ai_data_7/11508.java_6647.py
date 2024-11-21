class DisjointPattern:
    def __init__(self):
        pass

    def get_block(self, context: bool) -> 'PatternBlock':
        raise NotImplementedError("Subclasses must implement this method")

    def get_instruction_block(self) -> 'PatternBlock':
        return self.get_block(False)

    def get_context_block(self) -> 'PatternBlock':
        return self.get_block(True)

    def get_whole_instruction_bytes(self) -> bytes:
        block = self.get_instruction_block()
        if block is not None:
            return block.getwholebytes()
        return b''

    @property
    def num_disjoint(self):
        raise NotImplementedError("Subclasses must implement this method")

    def get_disjoint(self, i: int) -> 'DisjointPattern':
        raise NotImplementedError("Subclasses must implement this method")

    def get_mask(self, startbit: int, size: int, context: bool) -> int:
        block = self.get_block(context)
        if block is not None:
            return block.getmask(startbit, size)
        return 0

    def get_value(self, startbit: int, size: int, context: bool) -> int:
        block = self.get_block(context)
        if block is not None:
            return block.getvalue(startbit, size)
        return 0

    def get_length(self, context: bool) -> int:
        block = self.get_block(context)
        if block is not None:
            return block.getlength()
        return 0

    def specializes(self, op2: 'DisjointPattern') -> bool:
        a = self.get_block(False)
        b = op2.get_block(False)
        if b is not None and a is not None:
            if not a.specializes(b):
                return False
        a = self.get_block(True)
        b = op2.get_block(True)
        if b is not None and a is not None:
            if not a.specializes(b):
                return False
        return True

    def identical(self, op2: 'DisjointPattern') -> bool:
        a = self.get_block(False)
        b = op2.get_block(False)
        if b is not None and a is not None:
            if not a.identical(b):
                return False
        a = self.get_block(True)
        b = op2.get_block(True)
        if b is not None and a is not None:
            if not a.identical(b):
                return False
        return True

    @staticmethod
    def restore_disjoint(parser: 'XmlPullParser') -> 'DisjointPattern':
        el = parser.peek()
        res = None
        if el.name == "instruct_pat":
            res = InstructionPattern()
        elif el.name == "context_pat":
            res = ContextPattern()
        else:
            res = CombinePattern()
        res.restore_xml(parser)
        return res


class PatternBlock:
    def __init__(self):
        pass

    @property
    def wholebytes(self) -> bytes:
        raise NotImplementedError("Subclasses must implement this method")

    def getmask(self, startbit: int, size: int) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def getvalue(self, startbit: int, size: int) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def length(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")


class InstructionPattern(DisjointPattern):
    pass


class ContextPattern(DisjointPattern):
    pass


class CombinePattern(DisjointPattern):
    pass
