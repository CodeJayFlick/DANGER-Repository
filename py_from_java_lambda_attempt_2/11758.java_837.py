Here is the translation of the given Java code into Python:

```Python
class TripleSymbol:
    def __init__(self, location):
        pass  # equivalent to super(location)

    def __init__(self, location, nm):
        pass  # equivalent to super(location, nm)

    def get_pattern_expression(self):
        raise NotImplementedError("Method not implemented")

    def get_fixed_handle(self, hand, pos):
        raise NotImplementedError("Method not implemented")

    @property
    def size(self):
        return 0

    def print(self, s, pos):
        raise NotImplementedError("Method not implemented")

    def collect_local_values(self, results):
        pass  # equivalent to doing nothing by default

    def resolve(self, pos):
        return None


class PatternExpression:
    pass
```

Please note that the above Python code is a direct translation of the given Java code. It does not include any specific functionality or error handling as it was provided in the original Java code.