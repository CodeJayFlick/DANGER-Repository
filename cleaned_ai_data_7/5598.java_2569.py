class CodeUnitProxy:
    def __init__(self, model, program, cu):
        self.model = model
        self.program = program
        self.cu = cu
        self.addr = cu.get_min_address()

    @property
    def object(self):
        if self.cu is not None:
            try:
                return self.cu
            except Exception as e:  # catch all exceptions, including ConcurrentModificationException
                pass
        else:
            self.cu = self.program.listing.code_unit_at(self.addr)
            return self.cu

class ListingModel:
    def __init__(self):
        pass

class Program:
    def __init__(self):
        pass

    @property
    def listing(self):
        # assume this is a property that returns the program's listing object
        pass

class CodeUnit:
    def __init__(self, min_address):
        self.min_address = min_address

    @property
    def get_min_address(self):
        return self.min_address

    @property
    def code_unit_at(self, addr):
        # assume this is a method that returns the code unit at the given address
        pass
