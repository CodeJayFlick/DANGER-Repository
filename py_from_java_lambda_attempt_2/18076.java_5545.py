Here is the translation of the given Java code into Python:

```Python
class Operator:
    def __init__(self, token_int_type):
        self.token_int_type = token_int_type
        self.token_symbol = SQLConstant.get_token_symbol(token_int_type)

    @property
    def token_int_type(self):
        return self._token_int_type

    @property
    def token_symbol(self):
        return self._token_symbol

    def __str__(self):
        return str(self.token_symbol)
```

Note: I assume that `SQLConstant` is a class or module with a method `get_token_symbol(token_int_type)` to get the symbol for a given integer type.