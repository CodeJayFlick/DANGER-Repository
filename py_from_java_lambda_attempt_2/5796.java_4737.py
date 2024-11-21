Here is the translation of the given Java code into Python:

```Python
class MultiCodeUnitIterator:
    def __init__(self, listings, addr, forward):
        self.forward = forward
        self.iter = [listings[i].get_code_units(addr, forward) for i in range(len(listings))]
        self.cu = [None] * len(self.iter)

    def __init__(self, listings, addrs, forward):
        self.forward = forward
        self.iter = [listings[i].get_code_units(addrs, forward) for i in range(len(listings))]
        self.cu = [None] * len(self.iter)

    def has_next(self):
        for i in range(len(self.iter)):
            if self.cu[i] is not None or self.iter[i].has_next():
                return True
        return False

    def next(self):
        # Get a next value from each iterator
        for i in range(len(self.iter)):
            if self.cu[i] is None:
                if self.iter[i].has_next():
                    self.cu[i] = self.iter[i].next()
        
        # Find next code unit.
        cu_next = None
        next_cu = [False] * len(self.iter)
        for i in range(len(self.iter)):
            if self.cu[i] is not None:
                if cu_next is None:
                    cu_next = self.cu[i]
                    next_cu[i] = True
                else:
                    result = compare_address(cu_next, self.cu[i])
                    if result == 0:
                        next_cu[i] = True
                    elif (self.forward and result > 0) or not self.forward and result < 0:
                        cu_next = self.cu[i]
                        for n in range(i):
                            next_cu[n] = False
                        next_cu[i] = True
        
        # Load array with all code units that have same address as next. Others are null.
        next_cus = [None] * len(self.iter)
        for i in range(len(self.iter)):
            if next_cu[i]:
                next_cus[i] = self.cu[i]
                self.cu[i] = None
        return next_cus

    def compare_address(cu1, cu2):
        addr1 = cu1.get_min_address()
        addr2 = cu2.get_min_address()
        return (addr1 - addr2).total_seconds()

# Helper function to get code units from a listing.
def getCodeUnits(self, addr, forward):
    pass

class CodeUnitIterator:
    def __init__(self, listings):
        self.listings = listings
        self.iter = [None] * len(listings)

    def has_next(self):
        for i in range(len(self.iter)):
            if self.iter[i].has_next():
                return True
        return False

    def next(self):
        pass

class Listing:
    def __init__(self, code_units):
        self.code_units = code_units

    def get_code_units(self, addr, forward):
        # This method should be implemented based on the actual data structure.
        pass

    def getCodeUnits(self, addrs, forward):
        # This method should be implemented based on the actual data structure.
        pass
```

Please note that this is a direct translation of your Java code into Python. However, there are some differences between the two languages that may affect how the code works in practice:

1. In Python, you need to define classes and methods before they can be used.

2. The `getCodeUnits` method in the Listing class should be implemented based on the actual data structure of your listings.

3. Similarly, the `has_next`, `next`, and `compare_address` methods in the MultiCodeUnitIterator class should also be implemented based on how you want these iterators to work with your code units.

4. The comparison method used here (`total_seconds`) is not exactly equivalent to Java's `compareTo`. It may need to be adjusted depending on what kind of data you are working with and how you want them compared.