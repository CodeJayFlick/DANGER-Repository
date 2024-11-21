class FunctionBodyFunctionExtentGenerator:
    def calculate_extent(self, func):
        if not func:
            return []
        
        body = func.get_body()
        if not body:
            return []

        units = []
        program = func.get_program()
        listing = program.get_listing()

        for code_unit in listing.instructions(body, True):
            units.append(code_unit)

        return units
