import re
from typing import List, Tuple, Any

class ArithmeticExpression:
    def __init__(self):
        self.patterns = {
            r'\(%number%\)[\s]+[\%number%\]': {'operator': '+', 'left_grouped': True, 'right_grouped': True},
            r'\(%number%\)[\s]+[%number%]': {'operator': '+', 'left_grouped': True, 'right_grouped': False},
            r'%number%[\s]+[\%number%\]': {'operator': '+', 'left_grouped': False, 'right_grouped': True},
            r'%number%[\s]+[%number%]': {'operator': '+', 'left_grouped': False, 'right_grouped': False},

            r'\(%number%\)[\s]-[\%number%\]': {'operator': '-', 'left_grouped': True, 'right_grouped': True},
            r'\(%number%\)[\s]-[%number%]': {'operator': '-', 'left_grouped': True, 'right_grouped': False},
            r'%number%[\s]-[\%number%\]': {'operator': '-', 'left_grouped': False, 'right_grouped': True},
            r'%number%[\s]-[%number%]': {'operator': '-', 'left_grouped': False, 'right_grouped': False},

            r'\(%number%\)[\s]*[\%number%\]': {'operator': '*', 'left_grouped': True, 'right_grouped': True},
            r'\(%number%\)[\s]*[%number%]': {'operator': '*', 'left_grouped': True, 'right_grouped': False},
            r'%number%[\s]*[\%number%\]': {'operator': '*', 'left_grouped': False, 'right_grouped': True},
            r'%number%[\s]*[%number%]': {'operator': '*', 'left_grouped': False, 'right_grouped': False},

            r'\(%number%\)[\s]/[\%number%\]': {'operator': '/', 'left_grouped': True, 'right_grouped': True},
            r'\(%number%\)[\s]/[%number%]': {'operator': '/', 'left_grouped': True, 'right_grouped': False},
            r'%number%[\s]/[\%number%\]': {'operator': '/', 'left_grouped': False, 'right_grouped': True},
            r'%number%[\s]/[%number%]': {'operator': '/', 'left_grouped': False, 'right_grouped': False},

            r'\(%number%\)[\s]^[\%number%\]': {'operator': '**', 'left_grouped': True, 'right_grouped': True},
            r'\(%number%\)[\s]^[%number%]': {'operator': '**', 'left_grouped': True, 'right_grouped': False},
            r'%number%[\s]^[\%number%\]': {'operator': '**', 'left_grouped': False, 'right_grouped': True},
            r'%number%[\s]^[%number%]': {'operator': '**', 'left_grouped': False, 'right_grouped': False}
        }

    def register_expression(self):
        for pattern in self.patterns:
            Skript.register_expression(ArithmeticExpression, Number, ExpressionType.PATTERN_MATCHES_EVERYTHING, [pattern])

class ArithmeticGettable:
    @staticmethod
    def parse(chain: List[Any]) -> 'ArithmeticGettable':
        # implement parsing logic here

class ArithmeticChain:
    @staticmethod
    def parse(chain: List[Any]) -> 'ArithmeticGettable':
        # implement parsing logic here

class ExprArithmetic(ArithmeticExpression):
    def __init__(self, first_expression: Any, second_expression: Any, operator: str) -> None:
        self.first = first_expression
        self.second = second_expression
        self.op = operator

    @staticmethod
    def register_expression():
        ArithmeticExpression().register_expression()

    def init(self, exprs: List[Any], matched_pattern: int, is_delayed: bool, parse_result: Any) -> None:
        if isinstance(exprs[0], ExprArithmetic):
            chain.extend(((ExprArithmetic) first).chain)
        else:
            chain.append(first)

        chain.append(op)

        if isinstance(exprs[1], ExprArithmetic):
            chain.extend(((ExprArithmetic) second).chain)
        else:
            chain.append(second)

    def get(self, event: Any) -> List[Any]:
        one = [self.return_type(0)]

        return one

    @property
    def return_type(self) -> type:
        if self.op in ['/', '**']:
            return float
        elif isinstance(first_expression.get_return_type(), int) and isinstance(second_expression.get_return_type(), int):
            return long
        else:
            return float

    def is_single(self) -> bool:
        return True

    @property
    def first_expression(self) -> Any:
        return self.first

    @first_expression.setter
    def first_expression(self, value: Any) -> None:
        self.first = value

    @property
    def second_expression(self) -> Any:
        return self.second

    @second_expression.setter
    def second_expression(self, value: Any) -> None:
        self.second = value

    @property
    def op(self) -> str:
        return self.op

    @op.setter
    def op(self, value: str) -> None:
        self.op = value

class SimpleExpression(Expression):
    pass

class ExpressionType(Enum):
    PATTERN_MATCHES_EVERYTHING = 1

def get_array(event: Any) -> List[Any]:
    # implement logic here

if __name__ == "__main__":
    ExprArithmetic.register_expression()
