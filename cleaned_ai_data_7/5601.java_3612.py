class FunctionProxy:
    def __init__(self, model, program, location_addr, function):
        self.model = model
        self.program = program
        self.location_addr = location_addr
        self.function = function
        self.function_addr = function.get_entry_point()

    @property
    def location_address(self):
        return self.location_addr

    @property
    def function_address(self):
        return self.function_addr

    def get_object(self):
        if self.function is not None:
            try:
                self.function.get_entry_point()
                return self.function
            except Exception as e:
                pass  # Ignore any exceptions that occur while trying to access the function.
        
        self.function = None
        
        listing = self.program.get_listing()

        if self.location_addr != self.function_addr:  
            # Ensure that inferred function reference is valid
            cu = listing.get_code_unit_at(self.location_addr)
            if isinstance(cu, Data):
                data = cu
                ref = data.get_primary_reference(0)
                if ref and ref.to_address == self.function_addr:
                    return None  # If the referenced address does not match the function's entry point, return None.
        
        self.function = listing.get_function_at(self.function_addr)
        return self.function

class Data:
    def __init__(self):
        pass
    
    @property
    def data_type(self):
        raise NotImplementedError("Subclasses must implement this method.")

    def get_primary_reference(self, index):
        raise NotImplementedError("Subclasses must implement this method.")
