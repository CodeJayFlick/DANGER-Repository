Here is the equivalent Python code:

```Python
class SpecialNumber:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        return {
            "name": "Special Number",
            "description": "Special number values, namely NaN, Infinity and -Infinity",
            "examples": ["if {_number} is NaN value:"],
            "since": "2.2-dev32d"
        }

    @staticmethod
    def get_value(value):
        if value == 0:
            return float("NaN")
        elif value == 1:
            return float("inf")
        else:
            return -float("inf")

class SkriptParser:
    pass

def init(exprs, matched_pattern, is_delayed, parse_result):
    value = parse_result.mark
    return True

def get(event):
    values = []
    if value == 0:
        values.append(float("NaN"))
    elif value == 1:
        values.append(float("inf"))
    else:
        values.append(-float("inf"))
    return values

class Number:
    pass

def get_return_type():
    return Number

def is_single():
    return True

def to_string(event, debug):
    if value == 0:
        return "NaN value"
    elif value == 1:
        return "infinity value"
    else:
        return "-infinity value"

# Usage
value = SpecialNumber()
print(value.get_value(0))  # Output: nan
print(value.get_value(1))   # Output: inf
print(value.get_value(-1))  # Output: -inf

```

Please note that this is not a direct translation, but rather an equivalent Python code. The original Java code seems to be part of the Skript language and its expressions system, which does not have a direct equivalent in Python.