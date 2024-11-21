class CreateExternalFunctionCmd:
    def __init__(self):
        self.ext_symbol = None
        self.library_name = None
        self.parent_namespace = None
        self.name = None
        self.address = None
        self.source_type = None

    def create(self, ext_symbol=None, library_name=None, name=None, address=None, source_type=None):
        if not isinstance(ext_symbol, Symbol) and (ext_symbol is not None or name is None):
            raise ValueError("External symbol may not be null")
        self.ext_symbol = ext_symbol
        self.source_type = source_type

    def apply_to(self, obj):
        program = Program(obj)
        if self.ext_symbol is None:
            return self.create_external_function(program)

        if not isinstance(self.ext_symbol, Symbol) or self.ext_symbol.get_symbol_type() != 'LABEL':
            # status = "Invalid symbol specified"
            return False

        ext_loc = ExternalLocation(self.ext_symbol)
        function = ext_loc.create_function()
        self.ext_symbol = function.get_symbol()

        if self.ext_symbol.source_type != source_type:
            self.ext_symbol.set_source(source_type)

        return True

    def create_external_function(self, program):
        try:
            external_manager = program.external_manager
            if not isinstance(external_manager, ExternalManager):
                raise ValueError("Invalid input")

            if self.parent_namespace is None:
                ext_loc = external_manager.add_ext_function(library_name, name, address, source_type)
            else:
                ext_loc = external_manager.add_ext_function(self.parent_namespace, name, address, source_type)

            self.ext_symbol = ext_loc.get_symbol()
            return True
        except (DuplicateNameException, InvalidInputException) as e:
            # status = str(e)
            pass

    def get_status_msg(self):
        if hasattr(self, 'status'):
            return self.status
        else:
            return None

    def __str__(self):
        return "Create External Function"

class Program:
    def __init__(self, obj):
        self.obj = obj

    @property
    def external_manager(self):
        # This is a placeholder for the actual implementation.
        pass

class Symbol:
    def __init__(self, source_type=None):
        self.source_type = source_type

    @property
    def get_symbol_type(self):
        return 'LABEL'

    @property
    def set_source(self, source_type):
        # This is a placeholder for the actual implementation.
        pass

class ExternalLocation:
    def __init__(self, symbol):
        self.symbol = symbol

    def create_function(self):
        # This is a placeholder for the actual implementation.
        return None

    @property
    def get_symbol(self):
        return self.symbol

class SourceType:
    pass

class Namespace:
    def __init__(self, parent_namespace=None):
        self.parent_namespace = parent_namespace

    def is_external(self):
        # This is a placeholder for the actual implementation.
        return True

    @property
    def get_parent_namespace(self):
        return self.parent_namespace

class Library:
    UNKNOWN = None  # This should be replaced with an actual constant.

# Example usage:

cmd = CreateExternalFunctionCmd()
program = Program(None)
status = cmd.apply_to(program)

print(cmd.get_status_msg())
