Here's a translation of your Java code into Python:

```Python
class GreaterEqualEquation:
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

        cur = min_val

        count = 0
        while True:
            lhs_val = None
            val = next((v for v in semval if v <= cur[-1]), None)
            if not val:
                break
            
            for lhs_val in range(lhs_min, lhs_max + 1):
                if lhs_val < val:
                    continue
                
                if count == 0:
                    self.set_token_pattern(ExpressUtils.build_pattern(self.lhs, lhs_val, semval, cur))
                else:
                    self.set_token_pattern(get_token_pattern().do_or(
                        ExpressUtils.build_pattern(self.lhs, lhs_val, semval, cur)
                    ))
                
                count += 1

            if not ExpressUtils.advance_combo(cur, min_val, max_val):
                break
        
        if count == 0:
            raise SleighError("Greater than or equal constraint is impossible to match", self.lhs.location)

class VectorSTL(list): pass
```

Please note that Python does not have direct equivalent of Java's `Vector` class. The above code uses the built-in list type in Python, which provides similar functionality.

Also, please replace any other missing classes or functions with their actual implementations as they are specific to your application and may vary based on how you're using them.