class VariableProxy:
    def __init__(self, model, program, location_addr, fun, var):
        self.model = model
        self.program = program
        self.location_addr = location_addr
        self.var = var
        self.function_addr = fun.get_entry_point()
        if isinstance(var, Parameter):
            self.ordinal = (var).get_ordinal()
        first_var_node = var.get_first_storage_var_node()
        self.storage_addr = first_var_node.address if first_var_node else None
        self.first_use_offset = var.get_first_use_offset()

    def get_object(self):
        try:
            return self.var
        except Exception as e:
            pass

        if not self.storage_addr:
            return None

        listing = self.program.get_listing()
        function = listing.get_function_at(self.function_addr)
        if not function:
            return None

        if self.location_addr != self.function_addr:
            # ensure that inferred reference is valid
            cu = listing.get_code_unit_at(self.location_addr)
            if isinstance(cu, Data):
                data = cu
                ref = data.primary_reference(0) if data else None
                if not (ref and ref.to_address == self.function_addr):
                    return None

        if self.ordinal >= 0:
            return function.parameter(self.ordinal)

        vars = function.get_local_variables()
        for i, var in enumerate(vars):
            if self.first_use_offset != var.first_use_offset:
                continue
            if self.storage_addr == var.min_address:
                return var
        return None

    def get_location_address(self):
        return self.location_addr

    def get_function_address(self):
        return self.function_addr


class Parameter:
    def __init__(self, ordinal):
        self.ordinal = ordinal

    def get_ordinal(self):
        return self.ordinal


class Data:
    def __init__(self, primary_reference=None):
        self.primary_reference = lambda x: primary_reference if primary_reference else None
