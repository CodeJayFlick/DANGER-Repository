Here is the translation of the given Java code into equivalent Python:

```Python
class TokenSymbol:
    def __init__(self, location, token):
        self.location = location
        self.name = token.get_name()
        self.token = token

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        self._token = value

class SleighSymbol:
    pass  # This class is not fully implemented in the given Java code. It's assumed to be a base class.

symbol_type = enum('token_symbol')  # Enum equivalent of Java's symbol_ type

# Example usage
location = 'some_location'  # Assuming this can be any object that represents location.
token = Token()  # Assuming there is a token class with get_name method in Python.

ts = TokenSymbol(location, token)
print(ts.token)  # prints the given token
```

Please note that I've made some assumptions about the classes and methods used in your code. For example, `Token` has a `get_name()` method to retrieve its name.