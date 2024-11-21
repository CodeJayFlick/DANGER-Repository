Here is the translation of the given Java code into Python:

```Python
class FunctionDefinitionLocationDescriptor:
    def __init__(self, location, program, function_definition):
        self.location = location
        self.program = program
        self.function_definition = function_definition

    def get_references(self, accumulator, monitor=None):
        my_return_type = self.function_definition.return_type
        my_parameters = self.function_definition.arguments

        function_manager = self.program.get_function_manager()
        symbol_table = self.program.get_symbol_table()

        symbols = symbol_table.get_symbols(self.function_definition.name)
        while symbols.has_next():
            symbol = symbols.next()
            if not isinstance(symbol, FunctionSymbol):
                continue
            function_symbol = symbol
            symbol_id = function_symbol.id
            function = function_manager.get_function(symbol_id)

            signature = function.signature(True)
            their_parameters = signature.arguments

            if not self.is_same_parameters(my_parameters, their_parameters):
                continue

            if not my_return_type.equivalent(signature.return_type):
                continue

            accumulator.add(LocationReference(function_symbol.address))

    def is_same_parameters(self, my_parameters, their_parameters):
        if len(their_parameters) != len(my_parameters):
            return False

        for i in range(len(my_parameters)):
            my_definition = my_parameters[i]
            their_definition = their_parameters[i]
            if not my_definition.equivalent(their_definition):
                return False
        return True


class LocationReference:
    def __init__(self, address):
        self.address = address


class FunctionDefinition:
    def __init__(self, name, arguments, return_type):
        self.name = name
        self.arguments = arguments
        self.return_type = return_type

```

Please note that Python does not have direct equivalent of Java's generics. Also, the code is translated to a simpler form as it seems like you are trying to translate this for learning purposes and might want to add more functionality later on.