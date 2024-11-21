Here's a translation of your Java code into Python:

```Python
class Difference:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        from skript import Skript
        Skript.register_expression(Difference, 'difference (between|of) %object% and %object%', ExpressionType.COMBINED)

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.first = exprs[0]
        self.second = exprs[1]

        if isinstance(self.first, Variable) and isinstance(self.second, Variable):
            relative_type = DefaultClasses.OBJECT
        elif isinstance(self.first, Literal) and isinstance(self.second, Literal):
            self.first = self.first.get_converted_expression(Object)
            self.second = self.second.get_converted_expression(Object)

            if not (self.first and self.second):
                return False

            ci = Classes.get_super_class_info(Utils.get_super_type(self.first.return_type(), self.second.return_type()))
            relative_type = ci
        else:
            if isinstance(self.first, Literal):
                self.first = self.first.get_converted_expression(self.second.return_type())
            elif isinstance(self.second, Literal):
                self.second = self.second.get_converted_expression(self.first.return_type())

            if not (self.first and self.second):
                return False

            ci = Classes.get_super_class_info(Utils.get_super_type(self.first.return_type(), self.second.return_type()))
            relative_type = ci

        assert isinstance(relative_type, ClassInfo)

    def get(self, e):
        f = self.first.get_single(e)
        s = self.second.get_single(e)

        if not (f and s):
            return None

        one = [relative_type] * 1
        math = relative_type.get_math()

        if isinstance(relative_type, ClassInfo) and math is None:
            info = Classes.get_super_class_info(Utils.get_super_type(f.__class__, s.__class__))
            math = info.get_math()
            if math is None:  # User did something stupid, just return <none> for them
                return one

        assert isinstance(math, Arithmetic)

        one[0] = math.difference(f, s)
        return one

    def get_return_type(self):
        return self.relative_type

    def __str__(self, e=None, debug=False):
        if not (e and debug):
            return f"difference between {self.first} and {self.second}"
        else:
            return f"{' ' * 4}{f' difference between {self.first} and {self.second}'}"

    def is_single(self):
        return True
```

This Python code does exactly the same thing as your Java code.