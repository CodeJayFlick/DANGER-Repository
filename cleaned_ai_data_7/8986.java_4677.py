class DisplayableLocalVariableAddress:
    def __init__(self, function: 'Function', local_variable_address):
        self.function = function
        self.local_variable_address = local_variable_address

    @property
    def program(self) -> 'Program':
        return self.function.program

    @property
    def address(self) -> int:
        return self.local_variable_address

    def get_display_string(self, local_variable=None):
        if not local_variable:
            return "No Address"
        return f"Local {local_variable} at {self.local_variable_address}"

    def get_local_variable(self, function: 'Function', local_address_to_get) -> {'Variable'} | None:
        if not (function and local_address_to_get):
            return None
        for variable in function.get_local_variables():
            if variable.min_address == local_address_to_get:
                return variable
        return None

    def get_string(self, local_variable: 'Variable') -> str:
        return f"Local @ " if local_variable else ""

    def __str__(self):
        return self.get_display_string()

    def compare_to(self, other_displayable_address) -> int | None:
        if not other_displayable_address:
            return 1
        other_address = other_displayable_address.address
        if not self.local_variable_address and not other_address:
            return 0
        elif not self.local_variable_address:
            return -1
        elif not other_address:
            return 1
        else:
            return self.local_variable_address - other_address

class Program: pass
class Function: pass
class Variable: pass
