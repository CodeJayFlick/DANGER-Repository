Here is the translation of the given Java code into Python:

```Python
class ExprTimeState:
    def __init__(self):
        self.Skript = None  # equivalent to Skript in Java
        self.expression_type = "PROPERTY"  # equivalent to ExpressionType.PROPERTY in Java
        self.patterns = {
            "[the] (former|past|old) [state] [of] %~object%": {"before the event"},
            "%~object% before [the event]": None,
            "[the] (future|to-be|new) [state] [of] %~object%": {"after[-to-]?[wards| the event]*"}
        }

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result: dict):
        if is_delayed:
            print("Cannot use time states after the event has already passed", file=sys.stderr)
            return False
        try:
            self.expr = exprs[0]
            if not self.expr.set_time(matched_pattern >= 2 and -1 or 1):
                print(f"{self.expr} does not have a {'' if matched_pattern < 2 else 'future'} state", file=sys.stderr)
                return False
        except Exception as e:
            print(str(e), file=sys.stderr)
            return False
        self.set_expr(self.expr)
        return True

    def __str__(self, event: dict = None, debug: bool = False):
        if not hasattr(self, 'expr'):
            raise AttributeError("ExprTimeState has no expression")
        time_str = "past" if self.get_time() == -1 else "future"
        return f"the {time_str} state of {self.expr.__str__(event, debug)}"

    def set_time(self, time: int):
        return time == self.get_time()

# usage
expr_time_state = ExprTimeState()
```

Please note that Python does not have direct equivalent to Java's `@author`, `@Name`, `@Description` etc. annotations.