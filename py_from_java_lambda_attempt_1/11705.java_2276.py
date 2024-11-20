Here is the translation of the given Java code into Python:

```Python
class OperandEquation:
    def __init__(self, location, ind):
        self.location = location
        self.index = ind

    def gen_pattern(self, ops):
        ops[self.index] = ops.get(self.index)

    def operand_order(self, ct, order):
        sym = ct.get_operand(self.index)
        if not sym.is_marked():
            order.append(sym)
            sym.set_mark()

    def resolve_operand_left(self, state):
        sym = state.operands[self.index]
        if sym.is_offset_irrelevant():
            sym.offsetbase = -1
            sym.reloffset = 0
            return True
        elif state.base == -2:  # We have no base
            return False
        else:
            sym.offsetbase = state.base
            sym.reloffset = state.offset
            state.cur_rightmost = self.index
            state.size = 0  # Distance from right edge
            return True


class VectorSTL(list):
    def get(self, index):
        return self[index]

    def push_back(self, item):
        super().append(item)

    def append(self, item):
        super().append(item)
```

Please note that Python does not have direct equivalent of Java's `Vector` class. The above code uses the built-in list type to mimic its functionality.