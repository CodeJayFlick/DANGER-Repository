class DecompileData:
    def __init__(self, program: 'Program', function: 'Function', location: 'ProgramLocation',
                 decompile_results: 'DecompileResults', message: str, debug_file: object,
                 viewer_position: object):
        self.program = program
        self.function = function
        self.location = location
        self.decompile_results = decompile_results
        self.message = message
        self.debug_file = debug_file
        self.viewer_position = viewer_position

    def has_decompile_results(self) -> bool:
        if not self.decompile_results:
            return False
        return self.decompile_results.get_c_code_markup() is not None

    def get_decompile_results(self):
        return self.decompile_results

    def get_program(self):
        return self.program

    def get_function(self):
        return self.function

    def get_high_function(self) -> 'HighFunction':
        if self.decompile_results:
            return self.decompile_results.get_high_function()
        return None

    def get_location(self):
        return self.location

    def get_c_code_markup(self) -> object:
        if not self.decompile_results:
            return None
        return self.decompile_results.get_c_code_markup()

    def get_error_message(self) -> str:
        if self.message:
            return self.message
        elif not self.function:
            return "No Function"
        elif self.decompile_results and self.decompile_results.get_error_message():
            return self.decompile_results.get_error_message()
        else:
            return "Unknown Error"

    def get_debug_file(self):
        return self.debug_file

    def contains(self, program_location: 'ProgramLocation') -> bool:
        if not self.has_decompile_results():
            return False
        if program_location.program != self.program:
            return False
        address = program_location.address
        if not address:
            return False
        return self.function.get_body().contains(address)

    def get_function_space(self):
        return self.function.get_entry_point().get_address_space()

    def get_viewer_position(self):
        return self.viewer_position

class ProgramLocation:
    pass

class DecompileResults:
    def __init__(self, high_function: 'HighFunction'):
        self.high_function = high_function
        # Add other attributes and methods as needed

    def get_high_function(self) -> 'HighFunction':
        return self.high_function

    def get_error_message(self):
        pass  # Implement this method if necessary

    def get_c_code_markup(self):
        pass  # Implement this method if necessary

class HighFunction:
    pass
