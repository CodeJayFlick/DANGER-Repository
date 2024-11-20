class LessEqualEquation:
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
            lhs_val = lhs_min
            while lhs_val <= lhs_max and lhs_val <= next(cur_val):
                if lhs_val > next(cur_val):
                    break
                if not count:
                    self.set_token_pattern(ExpressUtils.build_pattern(self.lhs, lhs_val, semval, cur_val))
                else:
                    self.set_token_pattern(get_token_pattern().do_or(
                        ExpressUtils.build_pattern(self.lhs, lhs_val, semval, cur_val)
                    ))
                count += 1
                lhs_val = next(lhs_val)

            if not ExpressUtils.advance_combo(cur_val, min_val, max_val):
                break

        if not count:
            raise SleighError("Less than or equal constraint is impossible to match", self.lhs.location)
