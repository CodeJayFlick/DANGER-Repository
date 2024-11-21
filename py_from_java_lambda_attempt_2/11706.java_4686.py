Here is the translation of the given Java code into Python:

```Python
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
```

In this Python code, we define a class `OperandResolve` with the same attributes as in Java: `operands`, `base`, `offset`, `cur_rightmost`, and `size`. The constructor (`__init__`) initializes these attributes.