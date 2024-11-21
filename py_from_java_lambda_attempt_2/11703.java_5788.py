Here's your Java code translated into Python:

```Python
class NotEqualEquation:
    def __init__(self, location, l, r):
        super().__init__(location, l, r)

    def gen_pattern(self):
        lhs_min = self.lhs.min_value()
        lhs_max = self.lhs.max_value()
        semval = []
        min_val = []
        max_val = []
        cur_val = []

        for val in self.rhs.list_values():
            semval.append(val)
        self.rhs.get_min_max(min_val, max_val)

        cur_val = min_val
        count = 0

        while True:
            lhs_val = None
            val = self.rhs.get_sub_value(cur_val[0])
            for lhs_val in range(lhs_min, lhs_max + 1):
                if lhs_val == val:
                    continue
                if count == 0:
                    yield ExpressUtils.build_pattern(self.lhs, lhs_val, semval, cur_val)
                else:
                    yield from (ExpressUtils.build_pattern(self.lhs, lhs_val, semval, cur_val),) + self.get_token_pattern().do_or(ExpressUtils.build_pattern(self.lhs, lhs_val, semval, cur_val))
                count += 1
            if not ExpressUtils.advance_combo(cur_val, min_val, max_val):
                break

        if count == 0:
            raise SleighError("Notequal constraint is impossible to match", self.lhs.location)
```

Please note that Python doesn't support direct translation of Java code. The above Python code has been written manually based on the provided Java code and may not be identical in terms of functionality or syntax.