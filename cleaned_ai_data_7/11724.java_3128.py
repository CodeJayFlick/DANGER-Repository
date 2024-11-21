class DisjointPattern:
    def __init__(self):
        pass

    def get_block(self, context: bool) -> 'PatternBlock':
        raise NotImplementedError("get_block must be implemented")

    @property
    def num_disjoint(self) -> int:
        return 0

    def get_disjoint(self, i: int) -> 'DisjointPattern':
        return None

    def get_mask(self, startbit: int, size: int, context: bool) -> int:
        block = self.get_block(context)
        if block is not None:
            return block.get_mask(startbit, size)
        return 0

    def get_value(self, startbit: int, size: int, context: bool) -> int:
        block = self.get_block(context)
        if block is not None:
            return block.get_value(startbit, size)
        return 0

    def get_length(self, context: bool) -> int:
        block = self.get_block(context)
        if block is not None:
            return block.get_length()
        return 0

    def specializes(self, op2: 'DisjointPattern') -> bool:
        a = self.get_block(False)
        b = op2.get_block(False)
        if b is not None and not b.always_true():
            if a is None:
                return False
            if not a.specializes(b):
                return False

        a = self.get_block(True)
        b = op2.get_block(True)
        if b is not None and not b.always_true():
            if a is None:
                return False
            if not a.specializes(b):
                return False

        return True

    def identical(self, op2: 'DisjointPattern') -> bool:
        a = self.get_block(False)
        b = op2.get_block(False)
        if b is not None:
            if a is None and not b.always_true():
                return False
            elif a is not None and not a.identical(b):
                return False

        else:
            if a is not None and not a.always_true():
                return False

        a = self.get_block(True)
        b = op2.get_block(True)
        if b is not None:
            if a is None and not b.always_true():
                return False
            elif a is not None and not a.identical(b):
                return False

        else:
            if a is not None and not a.always_true():
                return False

        return True

    @staticmethod
    def resolve_intersect_block(bl1: 'PatternBlock', bl2: 'PatternBlock', thisblock: 'PatternBlock') -> bool:
        inter = None
        res = True

        if bl1 is None:
            inter = bl2
        elif bl2 is None:
            inter = bl1
        else:
            inter = bl1.intersect(bl2)

        if inter is None:
            if thisblock is not None:
                res = False
        elif thisblock is None:
            res = False
        else:
            res = thisblock.identical(inter)

        return res

    def resolves_intersect(self, op1: 'DisjointPattern', op2: 'DisjointPattern') -> bool:
        if not self.resolve_intersect_block(op1.get_block(False), op2.get_block(False), self.get_block(False)):
            return False
        return self.resolve_intersect_block(op1.get_block(True), op2.get_block(True), self.get_block(True))

    @staticmethod
    def restore_disjoint(el: 'Element') -> 'DisjointPattern':
        if el.name == "instruct_pat":
            res = InstructionPattern()
        elif el.name == "context_pat":
            res = ContextPattern()
        else:
            res = CombinePattern()

        res.restore_xml(el)
        return res

    def __str__(self) -> str:
        return f"DisjointPattern{{{self.get_block(True)} : {self.get_block(False)}}}"
