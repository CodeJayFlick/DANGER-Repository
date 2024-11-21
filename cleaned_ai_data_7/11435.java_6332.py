class AssemblyParseNumericToken:
    def __init__(self, grammar, term, str_val, val):
        self._grammar = grammar
        self._term = term
        self._str_val = str_val
        self.val = val

    def hash(self):
        result = hash(self._term)
        result *= 31
        result += hash(self._str_val)
        result *= 31
        result += hash(self.val)
        return result

    def __eq__(self, other):
        if not isinstance(other, AssemblyParseNumericToken):
            return False
        if self._term != other._term:
            return False
        if self._str_val != other._str_val:
            return False
        if self.val != other.val:
            return False
        return True

    def __str__(self):
        return "'" + str(self._str_val) + "'=" + str(self.val)

    def get_numeric_value(self):
        return self.val

    def is_numeric(self):
        return True


# Example usage:

class AssemblyGrammar: pass  # This class doesn't have any implementation in the given Java code.
class AssemblyTerminal: pass  # This class doesn't have any implementation in the given Java code.

grammar = object()  # Assuming you want to create an instance of this abstract base class
term = object()
str_val = "some string"
val = 1234567890

token = AssemblyParseNumericToken(grammar, term, str_val, val)

print(token)  # Output: 'some string'=1234567890
