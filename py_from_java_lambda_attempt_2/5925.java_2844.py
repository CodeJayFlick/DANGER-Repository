Here is a translation of the Java code into equivalent Python:

```Python
class FunctionNameTableColumn:
    def get_column_name(self):
        return "Function Name"

    def get_value(self, row_object: 'Address', settings=None, program=None) -> str | None:
        function = self.get_function_containing(row_object, program)
        if function is not None:
            return function.name
        return None

    def get_program_location(self, row_object: 'Address', settings=None, program=None) -> ProgramLocation | None:
        function = self.get_function_containing(row_object, program)
        if function is not None:
            return FunctionNameFieldLocation(program, function.entry_point, 0,
                                              function.prototype_string(False, False), function.name)
        return None

    def get_function_containing(self, row_object: 'Address', program) -> Function | None:
        addr = row_object
        return program.function_manager.get_function_containing(addr)

class ProgramLocation:
    pass

class Address:
    pass

class FunctionNameFieldLocation(ProgramLocation):
    def __init__(self, program, entry_point, offset, prototype_string, name):
        self.program = program
        self.entry_point = entry_point
        self.offset = offset
        self.prototype_string = prototype_string
        self.name = name

class Program:
    def get_function_manager(self) -> 'FunctionManager':
        pass

    def get_function_containing(self, addr: Address) -> Function | None:
        pass

class FunctionManager:
    def get_function_containing(self, addr: Address) -> Function | None:
        pass
```

Please note that Python does not have direct equivalent of Java's generics. The `Address` and other classes are defined as separate entities in the above code.