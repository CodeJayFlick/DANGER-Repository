Here is the translation of the given Java code into equivalent Python:

```Python
class UnionAddressSetView:
    def __init__(self, *views):
        self.views = list(views)

    def contains(self, addr):
        for v in self.views:
            if v.contains(addr):
                return True
        return False

    def is_empty(self):
        for v in self.views:
            if not v.is_empty():
                return False
        return True

    def get_min_address(self):
        result = None
        for v in self.views:
            cand_min = v.get_min_address()
            if cand_min is None:
                continue
            if result is None:
                result = cand_min
                continue
            result = min(result, cand_min)
        return result

    def get_max_address(self):
        result = None
        for v in self.views:
            cand_max = v.get_max_address()
            if cand_max is None:
                continue
            if result is None:
                result = cand_max
                continue
            result = max(result, cand_max)
        return result

    def get_address_ranges(self):
        from itertools import chain
        return chain(*[v for v in self.views])

    def get_address_ranges(self, forward=False):
        from itertools import chain
        return chain(*[v.get_range(forward) if not forward else reversed(v.get_range(not forward)) for v in self.views])

    def get_address_ranges(self, start, forward=True):
        rev = list(chain(*[reversed(v.get_range(start, False)) if not forward else v.get_range(start, True) for v in self.views]))
        fixed_start = self.fix_start(rev, start, forward)
        return chain(*[fixed_start] + [v.get_range(fixed_start, forward) for v in self.views])

    def fix_start(self, rev, start, forward):
        if not forward:
            rev.reverse()
        while len(rev) > 0 and (start is None or rev[-1].get_end() <= start):
            rev.pop()
        return rev[0] if len(rev) > 0 else None
```

Note that Python does not have direct equivalents for Java's `AddressSetView` class, so I had to make some assumptions about how the methods should be implemented.