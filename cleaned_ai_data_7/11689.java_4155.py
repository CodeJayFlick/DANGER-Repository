class EqualEquation:
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
            if (lhs_min <= val) and (val <= lhs_max):
                if not semval:
                    pattern = {'pattern': f'{self.lhs} == {val}', 'semval': semval, 'cur_val': [val]}
                    # setTokenPattern(ExpressUtils.buildPattern(lhs, val, semval, cur))
                    print(pattern)
                else:
                    pattern = {'pattern': f'({self.getTokenPattern().do_or(f"{self.lhs} == {val}")})', 'semval': semval, 'cur_val': [val]}
                    # setTokenPattern(getTokenPattern().doOr(ExpressUtils.buildPattern(lhs, val, semval, cur)))
                    print(pattern)
                self.count += 1
            else:
                min_val = self.rhs.get_min_max()[0]
                max_val = self.rhs.get_min_max()[1]

        if not self.count:
            raise Exception("Equal constraint is impossible to match", self.location)

    def getTokenPattern(self):
        # This method should return the token pattern
        pass

# Example usage:

location = 'Location'
l = PatternValue()
r = PatternExpression()

equation = EqualEquation(location, l, r)
equation.gen_pattern()
