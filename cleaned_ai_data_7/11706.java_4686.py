class OperandResolve:
    def __init__(self, operands):
        self.operands = operands
        self.base = -1
        self.offset = 0
        self.cur_rightmost = -1
        self.size = 0

# Example usage:
operands = ['op1', 'op2', 'op3']
obj = OperandResolve(operands)
print(obj.__dict__)
