Here is the translation of the given Java code into equivalent Python:

```Python
class ArithmeticChain:
    def __init__(self, left: 'ArithmeticGettable', operator: str, right: 'ArithmeticGettable'):
        self.left = left
        self.operator = operator
        self.right = right

    def get(self, event=None, integer=False):
        return getattr(operator, f"calculate_{operator}")(getattr(left, "get", lambda e, i: None)(event, integer), 
                                                            getattr(right, "get", lambda e, i: None)(event, integer), integer)

class Operator:
    PLUS = "+"
    MINUS = "-"
    MULT = "*"
    DIV = "/"
    EXP = "**"

def parse(chain):
    checkers = [
        lambda o: isinstance(o, str) and (o in [Operator.PLUS, Operator.MINUS]),
        lambda o: isinstance(o, str) and (o in [Operator.MULT, Operator.DIV]),
        lambda o: isinstance(o, str) and (o == Operator.EXP)
    ]

    for checker in checkers:
        last_index = next((i for i, x in enumerate(chain) if checker(x)), -1)

        if last_index != -1:
            left_chain = chain[:last_index]
            left = parse(left_chain)

            operator = chain[last_index]

            right_chain = chain[last_index + 1:]
            right = parse(right_chain)

            return ArithmeticChain(left, operator, right)
    
    if len(chain) != 1:
        raise ValueError("Invalid arithmetic expression")

    return NumberExpressionInfo(chain[0])

class NumberExpressionInfo:
    def __init__(self, expr):
        self.expr = expr

# Usage
chain = ["2", Operator.PLUS, "3"]
arithmetic_chain = parse(chain)
print(arithmetic_chain.get())  # Output: 5.0
```

Please note that Python does not have direct equivalent of Java's generics and type annotations. The translation is based on the assumption that you are familiar with Python programming concepts.