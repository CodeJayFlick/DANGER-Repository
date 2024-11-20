Here is the translation of the given Java code into Python:

```Python
class PatternExpression:
    def __init__(self, location):
        self.location = location
        self.refcount = 0

    def dispose(self):
        pass  # Only delete through release

    @abstractmethod
    def get_value(self, pos):
        pass

    @abstractmethod
    def gen_min_pattern(self, ops):
        pass

    @abstractmethod
    def list_values(self, list):
        pass

    @abstractmethod
    def get_min_max(self, minlist, maxlist):
        pass

    @abstractmethod
    def get_sub_value(self, replace, listpos):
        pass

    def save_xml(self, s):
        pass  # Not implemented in the original Java code

    def restore_xml(self, el, trans):
        pass  # Not implemented in the original Java code

    def lay_claim(self):
        self.refcount += 1

    @staticmethod
    def release(p):
        p.refcount -= 1
        if p.refcount <= 0:
            p.dispose()

    @staticmethod
    def restore_expression(el, trans):
        res = None
        nm = el.get_name()
        
        if nm == "tokenfield":
            res = TokenField(None)
        elif nm == "contextfield":
            res = ContextField(None)
        elif nm == "intb":
            res = ConstantValue(None)
        elif nm == "operand_exp":
            res = OperandValue(None)
        elif nm == "start_exp":
            res = StartInstructionValue(None)
        elif nm == "end_exp":
            res = EndInstructionValue(None)
        elif nm == "plus_exp":
            res = PlusExpression(None)
        elif nm == "sub_exp":
            res = SubExpression(None)
        elif nm == "mult_exp":
            res = MultExpression(None)
        elif nm == "lshift_exp":
            res = LeftShiftExpression(None)
        elif nm == "rshift_exp":
            res = RightShiftExpression(None)
        elif nm == "and_exp":
            res = AndExpression(None)
        elif nm == "or_exp":
            res = OrExpression(None)
        elif nm == "xor_exp":
            res = XorExpression(None)
        elif nm == "div_exp":
            res = DivExpression(None)
        elif nm == "minus_exp":
            res = MinusExpression(None)
        elif nm == "not_exp":
            res = NotExpression(None)
        else:
            return None

        if res is not None:
            res.restore_xml(el, trans)

        return res
```

Note that the `@abstractmethod` decorator in Python does not exist. Instead, you can use a regular method with no implementation to indicate an abstract method.

Also note that some methods like `save_xml`, `restore_xml`, and others are not implemented as they were not present in the original Java code.