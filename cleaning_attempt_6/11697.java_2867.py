class GreaterEquation:
    def __init__(self, location, l, r):
        super().__init__(location, l, r)

    def gen_pattern(self):
        lhs_min = self.lhs.min_value()
        lhs_max = self.lhs.max_value()
        semval = []
        min_val = []
        max_val = []
        cur = []

        for val in self.rhs.list_values():
            semval.append(val)
        
        self.rhs.get_min_max(min_val, max_val)

        current = min_val
        count = 0

        while True:
            lhs_val = None
            value = next((v for v in semval if v <= cur[0]), None)
            for val in range(lhs_min, lhs_max + 1):
                if val > value:
                    break
                if count == 0:
                    yield ExpressUtils.build_pattern(self.lhs, val, semval, current)
                else:
                    yield from (pattern.do_or(ExpressUtils.build_pattern(self.lhs, val, semval, current)) for pattern in self.get_token_patterns())
                count += 1

            if not ExpressUtils.advance_combo(current, min_val, max_val):
                break
        
        if count == 0:
            raise SleighError("Greater than constraint is impossible to match", self.lhs.location)
