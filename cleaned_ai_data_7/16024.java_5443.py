class PtNDArrayEx:
    def __init__(self, parent):
        self.array = parent

    def rdiv(self, n):
        return self.rdiv(n)

    def rdivi(self, b):
        if isinstance(b, (int, float)):
            return self.array / b
        else:
            raise TypeError("Expected int or float")

    def rsub(self, n):
        raise NotImplementedError

    def rsubi(self, b):
        raise NotImplementedError

    # ... and so on for all the other methods.

# Usage example:

pt_array = PtNDArrayEx(None)  # Initialize with a parent array
result1 = pt_array.rdiv(2.0)
print(result1)

try:
    result2 = pt_array.rsubi("hello")
except TypeError as e:
    print(e)
