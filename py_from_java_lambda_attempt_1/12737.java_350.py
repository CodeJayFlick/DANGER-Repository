Here is your Java code translated into Python:

```Python
class AddressEvaluator:
    TOKEN_CHARS = "+-*/()<>|^&~="

    def evaluate(self, p: 'Program', base_addr=None, s=''):
        af = p.get_address_factory()
        st = p.get_symbol_table()

        if base_addr is not None:
            list_ = [base_addr]
        else:
            list_ = []

        if not self.parse_to_list(s, af, st, list_):
            return None

        obj = self.eval(list_)
        if isinstance(obj, Address):
            return obj
        elif isinstance(obj, int):
            try:
                return af.get_default_address_space().get_address(obj)
            except Exception as e:
                pass  # ignore exception

    def evaluate_to_long(self, s=''):
        list_ = []

        if not self.parse_to_list(s, None, None, list_):
            return None

        obj = self.eval(list_)
        if isinstance(obj, Address):
            return obj.get_offset()
        elif isinstance(obj, int):
            return obj
        else:
            return None

    def parse_to_list(self, s: str, af=None, st=None, list_: list=[]):
        parser = s.split(TOKEN_CHARS)
        lookahead = ''
        while lookahead or len(parser) > 0:
            token = ''
            if lookahead:
                token = lookahead
                lookahead = ''
            else:
                token = parser.pop(0)

            if token == ' ':
                continue

            # =
            if token in ['=', '<', '>']:
                lookahead = parser[0]
                token = self.check_double_token(token, lookahead)
                if len(token) > 1:  # consumed lookahead
                    lookahead = ''
                else:
                    list_.append(self.get_value_object(st, af, token))
            elif token == '(':  # grouped expression
                start_index = parser.index(')')
                obj = self.eval(parser[:start_index] + [''])
                if obj is None:
                    return False
                for i in range(start_index):
                    parser.pop(0)
                list_.extend(obj)

    def check_double_token(self, tok: str, lookahead: str) -> str:
        switcher = {
            '=': lambda x: '==' if x == '=' else '=',
            '<': lambda x: '<=' if x == '<' and lookahead == '=' else '<',
            '>': lambda x: '>=' if x == '>' and lookahead == '=' else '>',
        }
        return switcher.get(tok, lambda x: x)(lookahead)

    def get_value_object(self, st=None, af=None, tok: str) -> object:
        try:
            start = 0
            radix = 10
            if s.startswith('0x'):
                start = 2
                radix = 16

            return (radix == 10) and int(s[start:]) or int.from_bytes(bytes.fromhex(s), 'big')

        except Exception as e:  # ignore exception
            pass

    def eval(self, list_: list):
        while True:
            done = False
            for i in range(len(list_)):
                obj = list_[i]
                if isinstance(obj, Operator):
                    done = self.evaluate_operator(list_, obj)
                    break
            else:  # no operator found
                return None

    def evaluate_operator(self, list_: list, op1=None, op2=None) -> bool:
        while True:
            for i in range(len(list_)):
                if isinstance(list_[i], Operator):
                    done = False
                    for j in range(i - 1, len(list_) + 1):  # find matching parenthesis
                        obj = list_.pop(j)
                        if isinstance(obj, Operator) and obj == op2:
                            return True

    def compute_value(self, v1: object, op: 'Operator', v2: object):
        switcher = {
            Operator.TIMES: lambda x, y: int(x * y),
            Operator.DIVIDE: lambda x, y: int(x / y) if isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
                else None,
            # ... other operators
        }
        return switcher.get(op.name.lower(), lambda x, y: None)(v1, v2)

    def get_difference(self, v1: object, v2: object):
        if isinstance(v1, Address) and isinstance(v2, int):
            return (v1 - v2).get_offset()
        elif isinstance(v1, int) and isinstance(v2, int):
            return v1 - v2
        else:
            return None

    def find_matching_paren(self, list_: list, index: int) -> int:
        depth = 0
        for j in range(index + 1, len(list_)):
            obj = list_[j]
            if isinstance(obj, Operator):
                depth += 1
            elif isinstance(obj, str) and obj == ')':
                return j

    def __init__(self):
        pass


class Program:
    @property
    def address_factory(self):
        # implement your logic here
        pass

    @property
    def symbol_table(self):
        # implement your logic here
        pass


class Address:
    def get_offset(self) -> int:
        return 0  # implement your logic here

    def add_wrap(self, offset: int) -> 'Address':
        return self  # implement your logic here

    @property
    def default_address_space(self):
        # implement your logic here
        pass


class Operator(str):
    PLUS = "+"
    MINUS = "-"
    TIMES = "*"
    DIVIDE = "/"
    AND = "&"
    OR = "|"
    NOT = "~"
    XOR = "^"
    LEFTSHIFT = "<<"
    RIGHTSHIFT = ">>"
    LEFT_PAREN = "("
    RIGHT_PAREN = ")"
    EQUALS = "=="
    NOTEQUALS = "!="
    LESS = "<"
    GREATER = ">"

    def __init__(self, name: str):
        super().__init__()
```

Please note that you need to implement the logic for `Program`, `Address` and their methods in your Python code.